#!/usr/bin/env python3
"""Migrate or preserve the FRP server authentication token without printing it."""
import sys
if sys.version_info < (3, 7):
    sys.stderr.write('ERROR: python 3.7 or newer is required\n')
    raise SystemExit(1)
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


class MigrationError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def semantic_fingerprint(data: bytes) -> str:
    return sha256_hex(data.strip())


def atomic_write_bytes(path: Path, data: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_write_json(path: Path, data, mode=0o600):
    payload = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()
    atomic_write_bytes(path, payload, mode)


def strip_toml_comment(s: str) -> str:
    in_str = False
    quote = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_str:
            if c == '\\' and quote == '"':
                i += 2
                continue
            if c == quote:
                in_str = False
                quote = None
            i += 1
            continue
        if c in '"\'':
            in_str = True
            quote = c
            i += 1
            continue
        if c == '#':
            return s[:i]
        i += 1
    return s


def unescape_basic(s: str) -> str:
    return (
        s.replace(r'\"', '"')
        .replace(r'\\', '\\')
        .replace(r'\n', '\n')
        .replace(r'\t', '\t')
    )


def parse_toml_value(raw: str) -> str:
    s = strip_toml_comment(raw).strip()
    if s.startswith('"""') and s.endswith('"""') and len(s) >= 6:
        return unescape_basic(s[3:-3])
    if s.startswith("'''") and s.endswith("'''") and len(s) >= 6:
        return s[3:-3]
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return unescape_basic(s[1:-1])
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1]
    return s


def _split_key_value(raw: str):
    if '=' not in raw:
        return None, None
    key, value = raw.split('=', 1)
    return key.strip(), value.strip()


def parse_frps_auth(toml_path: Path):
    """Return (inline_token_or_None, token_file_path_or_None). Never log values."""
    inline = None
    token_file = None
    section = ''
    try:
        text = toml_path.read_text(encoding='utf-8')
    except OSError as exc:
        raise MigrationError('unable to read existing FRP server configuration') from exc

    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith('#'):
            continue
        if raw.startswith('[') and raw.endswith(']'):
            section = raw[1:-1].strip()
            continue
        key, value = _split_key_value(raw)
        if not key:
            continue
        dotted = f'{section}.{key}' if section and not key.startswith('auth.') else key
        if key == 'auth.token' or (section == 'auth' and key == 'token'):
            inline = parse_toml_value(value)
        elif (
            key == 'auth.tokenSource.file.path'
            or dotted == 'auth.tokenSource.file.path'
            or (section == 'auth.tokenSource.file' and key == 'path')
        ):
            token_file = parse_toml_value(value)
    return inline, token_file


def resolve_token_file(toml_path: Path, token_file: str) -> Path:
    src = Path(token_file)
    if not src.is_absolute():
        src = toml_path.parent / src
    return src


def existing_token_bytes(etc_dir: Path):
    """Locate existing token bytes and a source label. Does not print the value."""
    token_path = etc_dir / 'server_token'
    toml_path = etc_dir / 'frps.toml'

    if token_path.is_file() and token_path.stat().st_size > 0:
        return token_path.read_bytes(), 'server_token', token_path

    if not toml_path.is_file():
        return None, None, None

    inline, token_file = parse_frps_auth(toml_path)
    if token_file:
        src = resolve_token_file(toml_path, token_file)
        if src.is_file() and src.stat().st_size > 0:
            return src.read_bytes(), 'token_file', src
    if inline:
        return inline.encode('utf-8'), 'inline', None

    raise MigrationError(
        'existing FRP configuration was found but no authentication token could be recovered'
    )


def backup_frps_toml(etc_dir: Path):
    toml_path = etc_dir / 'frps.toml'
    if not toml_path.is_file():
        return None
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = etc_dir / f'frps.toml.pre-drlink-{stamp}'
    if backup.exists():
        backup = etc_dir / f'frps.toml.pre-drlink-{stamp}-{os.getpid()}'
    data = toml_path.read_bytes()
    atomic_write_bytes(backup, data, 0o600)
    return backup


def generate_token_bytes() -> bytes:
    try:
        return subprocess.check_output(['openssl', 'rand', '-hex', '32'], stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MigrationError('failed to generate a new FRP token') from exc


def ensure_server_token(etc_dir: Path, backup=True):
    etc_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_frps_toml(etc_dir) if backup else None
    token_path = etc_dir / 'server_token'

    existing, source, source_path = existing_token_bytes(etc_dir)
    before_fp = semantic_fingerprint(existing) if existing is not None else None

    if source == 'server_token':
        os.chmod(token_path, 0o600)
        action = 'reused_server_token'
    elif existing is not None:
        atomic_write_bytes(token_path, existing, 0o600)
        action = 'migrated_inline' if source == 'inline' else 'migrated_token_file'
    else:
        atomic_write_bytes(token_path, generate_token_bytes(), 0o600)
        action = 'generated'

    if not token_path.is_file() or token_path.stat().st_size == 0:
        raise MigrationError('FRP server token file is missing after migration')
    os.chmod(token_path, 0o600)

    after_fp = semantic_fingerprint(token_path.read_bytes())
    preserved = 'N/A'
    if before_fp is not None:
        if before_fp != after_fp:
            raise MigrationError('existing FRP token fingerprint changed during migration')
        preserved = 'PASS'

    return {
        'action': action,
        'preserved': preserved,
        'backup': str(backup_path) if backup_path else '',
        'source_path': str(source_path) if source_path else '',
    }


def coerce_port(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def parse_ports_csv(ports_csv: str):
    ports = []
    for item in (ports_csv or '').split(','):
        port = coerce_port(item.strip())
        if port is not None:
            ports.append(port)
    return ports


def is_service_port(port, port_start, port_end, allocator_port):
    if port is None:
        return False
    if allocator_port is not None and port == int(allocator_port):
        return False
    return int(port_start) <= port <= int(port_end)


REGISTRY_SCHEMA_VERSION = 2


def unsupported_registry_message(state=None):
    version = None
    if isinstance(state, dict) and 'schema_version' in state:
        version = state.get('schema_version')
    shown = 1 if version is None else version
    return (
        f'unsupported registry schema version {shown}.\n\n'
        'This release requires registry schema version 2.\n\n'
        'Back up the existing registry and redeploy/reset it explicitly before continuing.'
    )


def load_registry_json(path: Path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError('unable to read an existing FRP registry') from exc
    if not isinstance(data, dict):
        raise MigrationError('existing FRP registry has an unexpected format')
    return data


def require_registry_v2(state):
    if not isinstance(state, dict):
        raise MigrationError(unsupported_registry_message(state))
    if state.get('schema_version') != REGISTRY_SCHEMA_VERSION:
        raise MigrationError(unsupported_registry_message(state))
    clients = state.get('clients', {})
    if clients is None:
        clients = {}
    if not isinstance(clients, dict):
        raise MigrationError(unsupported_registry_message(state))
    for client in clients.values():
        if not isinstance(client, dict):
            raise MigrationError(unsupported_registry_message(state))
        if 'ssh_port' in client or 'https_port' in client:
            raise MigrationError(
                'unsupported registry schema version 2.\n\n'
                'Legacy SSH/HTTPS fields are present. This release requires the generic multi-service registry.\n\n'
                'Back up the existing registry and redeploy/reset it explicitly before continuing.'
            )
        services = client.get('services', {})
        if services is None:
            services = {}
        if not isinstance(services, dict):
            raise MigrationError(unsupported_registry_message(state))
    reserved = state.get('reserved', [])
    if reserved is None:
        reserved = []
    if not isinstance(reserved, list):
        raise MigrationError(unsupported_registry_message(state))
    return state


def collect_used_ports(state, port_start, port_end, allocator_port):
    used = set()
    for item in state.get('reserved', []) or []:
        port = coerce_port(item)
        if is_service_port(port, port_start, port_end, allocator_port):
            used.add(port)
    for client in (state.get('clients') or {}).values():
        if not isinstance(client, dict):
            continue
        services = client.get('services') or {}
        if not isinstance(services, dict):
            continue
        for svc in services.values():
            if not isinstance(svc, dict):
                continue
            port = coerce_port(svc.get('remote_port'))
            if port is None:
                continue
            if allocator_port is not None and port == int(allocator_port):
                continue
            used.add(port)
    return used


def registry_result(action, legacy_migration, migrated_clients, preserved_ports, backup=None):
    return {
        'action': action,
        'legacy_migration': legacy_migration,
        'migrated_clients': int(migrated_clients),
        'preserved_ports': int(preserved_ports),
        'backup': str(backup) if backup else '',
    }


def init_registry(
    registry_path: Path,
    ports_csv: str,
    port_start=1,
    port_end=65535,
    allocator_port=None,
):
    port_start = int(port_start)
    port_end = int(port_end)
    if allocator_port is not None:
        allocator_port = int(allocator_port)

    active_ports = {
        port for port in parse_ports_csv(ports_csv)
        if is_service_port(port, port_start, port_end, allocator_port)
    }

    if registry_path.exists():
        state = require_registry_v2(load_registry_json(registry_path))
        used = collect_used_ports(state, port_start, port_end, allocator_port)
        return registry_result('unchanged', 'N/A', 0, len(used))

    state = {
        'schema_version': REGISTRY_SCHEMA_VERSION,
        'reserved': sorted(active_ports),
        'clients': {},
    }
    used = collect_used_ports(state, port_start, port_end, allocator_port)
    used.update(active_ports)
    atomic_write_json(registry_path, state, 0o600)
    return registry_result('created', 'N/A', 0, len(used))


def emit(result):
    # Controlled KEY=value only. Never print token material or fingerprints.
    print(f"TOKEN_ACTION={result['action']}")
    print(f"TOKEN_PRESERVED={result['preserved']}")
    if result.get('backup'):
        print(f"TOKEN_BACKUP={result['backup']}")


def emit_registry(result):
    # Counts only. Never print machine IDs, hostnames, or port-to-client maps.
    print(f"REGISTRY_ACTION={result['action']}")
    print(f"LEGACY_REGISTRY_MIGRATION={result['legacy_migration']}")
    print(f"MIGRATED_CLIENTS={result['migrated_clients']}")
    print(f"PRESERVED_PORTS={result['preserved_ports']}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Preserve FRP server tokens during install/migration')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_ensure = sub.add_parser('ensure')
    p_ensure.add_argument('--etc-dir', required=True)
    p_ensure.add_argument('--backup', action='store_true')

    p_reg = sub.add_parser('init-registry')
    p_reg.add_argument('--registry', required=True)
    p_reg.add_argument('--ports', default='')
    p_reg.add_argument('--port-start', type=int, default=1)
    p_reg.add_argument('--port-end', type=int, default=65535)
    p_reg.add_argument('--allocator-port', type=int, default=None)

    args = parser.parse_args(argv)
    try:
        if args.cmd == 'ensure':
            emit(ensure_server_token(Path(args.etc_dir), backup=args.backup))
        elif args.cmd == 'init-registry':
            emit_registry(
                init_registry(
                    Path(args.registry),
                    args.ports,
                    port_start=args.port_start,
                    port_end=args.port_end,
                    allocator_port=args.allocator_port,
                )
            )
    except MigrationError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    except Exception:
        print('ERROR: FRP server migration failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
