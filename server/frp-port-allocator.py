#!/usr/bin/env python3
import sys
if sys.version_info < (3, 7):
    sys.stderr.write('ERROR: python 3.7 or newer is required\n')
    raise SystemExit(1)
import argparse
import base64
import fcntl
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOCK = threading.Lock()
MAX_CLOCK_SKEW = 300
MGMT_NONCE_TTL = 900
# Idle AI claim polls (AI_AGENT_IDLE_POLL_SECONDS in lib/drlink_ai_agent.py)
# must fit inside the non-evictable replay horizon (2 * MAX_CLOCK_SKEW)
# without crowding out operator management requests. Evicting a nonce that
# is still inside that horizon would re-enable a valid signed replay.
AI_IDLE_POLL_SECONDS = 2.0
MGMT_NONCE_RESERVE = 64
MAX_NONCES_PER_CLIENT = int((2 * MAX_CLOCK_SKEW) / AI_IDLE_POLL_SECONDS) + MGMT_NONCE_RESERVE
REGISTRY_SCHEMA_VERSION = 2
SERVICE_ID_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$')
MAX_SERVICES = 32
MAX_NAME_LEN = 64
MAX_HOST_LEN = 253
ALLOWED_PRESETS = ('ssh', 'http', 'https', 'custom')
ALLOWED_PROTOCOLS = ('tcp',)
NONCE_RE = re.compile(r'^[0-9a-f]{64}$')
BOOTSTRAP_TICKET_PREFIX = 'bt1'
BOOTSTRAP_ID_HEX_LEN = 16
BOOTSTRAP_SECRET_HEX_LEN = 64
BOOTSTRAP_TICKET_MAX_LEN = 160
COMPACT_CREDENTIAL_BYTES = 16
COMPACT_CREDENTIAL_RE = re.compile(r'^[A-Za-z0-9_-]{22}$')
BOOTSTRAP_ALLOCATE_ATTEMPTS = 8
BOOTSTRAP_DUMMY_HASH = '0' * 64
HEX_RE = re.compile(r'^[0-9a-f]+$')
MACHINE_ID_MAX_LEN = 128
# Bounded Zero-Touch issuance (server-enforced; not CLI-only).
ZERO_TOUCH_MAX_PER_ISSUE = 10
ZERO_TOUCH_MAX_ACTIVE_UNUSED = 10
ZERO_TOUCH_USE_COUNT = 1
ZERO_TOUCH_DEFAULT_TTL_SEC = 3600
ZERO_TOUCH_MAX_TTL_SEC = 24 * 3600
HOSTNAME_MAX_LEN = 253
# Request body already caps at 64KiB; also bound idle reads and fan-out.
ALLOCATOR_REQUEST_TIMEOUT_SEC = 30
# TLS handshake runs in a worker after accept(); keep this short so stalled
# ClientHello cannot monopolize the accept loop or hold slots for long.
ALLOCATOR_TLS_HANDSHAKE_TIMEOUT_SEC = float(
    os.environ.get('FRP_ALLOCATOR_TLS_HANDSHAKE_TIMEOUT_SEC', '8')
)
ALLOCATOR_MAX_CONCURRENT = 32
_REQUEST_SLOTS = threading.BoundedSemaphore(ALLOCATOR_MAX_CONCURRENT)


def _load_mgmt_auth():
    candidates = [
        Path(__file__).resolve().parent / 'frp_mgmt_auth.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_mgmt_auth.py',
    ]
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_mgmt_auth', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise RuntimeError('missing frp_mgmt_auth.py')


MGMT = _load_mgmt_auth()


def _load_service_profiles():
    for path in (
        Path(__file__).resolve().parent / 'frp_service_profiles.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_service_profiles.py',
    ):
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_service_profiles', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


PROF = _load_service_profiles()


def _load_client_registry():
    candidates = [
        Path(__file__).resolve().parent / 'frp_client_registry.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_client_registry.py',
        Path('/usr/local/lib/drlink/frp_client_registry.py'),
    ]
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_client_registry', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise RuntimeError('missing frp_client_registry.py')


CREG = _load_client_registry()


def _load_runtime_policy():
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    candidates = [
        Path(__file__).resolve().parent / 'drlink_runtime_policy.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'drlink_runtime_policy.py',
        Path('/usr/local/lib/drlink/drlink_runtime_policy.py'),
    ]
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'drlink_runtime_policy.py')
        candidates.insert(0, Path(root) / 'lib' / 'drlink_runtime_policy.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('drlink_runtime_policy', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


RP = _load_runtime_policy()


def _load_mgmt_sync():
    candidates = [
        Path(__file__).resolve().parent / 'drlink_mgmt_sync.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'drlink_mgmt_sync.py',
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT') or ''
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'drlink_mgmt_sync.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('drlink_mgmt_sync', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


MGMT_SYNC = _load_mgmt_sync()


def _open_control_plane(cfg):
    if RP is None:
        return None
    try:
        return RP.open_plane(cfg)
    except Exception as exc:
        print('allocator control-plane open failed: %s' % exc, flush=True)
        return None


def sync_enrollment_to_control_plane(cfg, client, machine_id):
    """Persist enrolled client inventory into SQLite (authoritative).

    The allocator may also maintain a derived enrollment inventory projection
    under /var/lib/drlink/runtime/ for transport/reconcile, but SQLite is SSOT.
    """
    if RP is None or not isinstance(client, dict) or not machine_id:
        return
    try:
        plane = RP.open_plane(cfg)
    except Exception as exc:
        print('allocator control-plane open failed: %s' % exc, flush=True)
        return
    try:
        addresses = []
        observed = client.get('observed') if isinstance(client.get('observed'), dict) else {}
        for key in ('source_ip', 'last_source_ip'):
            addr = str(observed.get(key) or client.get(key) or '').strip()
            if addr:
                addresses.append({'address': addr, 'active': True})
        hostname = str(client.get('hostname') or '')
        label = str(client.get('label') or hostname or '')
        RP.sync_enrolled_client(
            plane,
            client_id=str(machine_id),
            hostname=hostname,
            label=label,
            description=str(client.get('note') or client.get('description') or ''),
            services=client.get('services') if isinstance(client.get('services'), dict) else {},
            addresses=addresses,
            connected=True,
        )
    except Exception as exc:
        print('allocator control-plane sync failed: %s' % exc, flush=True)
    finally:
        try:
            plane.close()
        except Exception:
            pass


def _load_machine_id():
    for path in (
        Path(__file__).resolve().parent / 'frp_machine_id.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_machine_id.py',
        Path('/usr/local/lib/drlink/frp_machine_id.py'),
    ):
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_machine_id', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


MID = _load_machine_id()

def _load_bounded():
    for path in (
        Path(__file__).resolve().parent / 'frp_bounded_server.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_bounded_server.py',
        Path('/usr/local/lib/drlink/frp_bounded_server.py'),
    ):
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_bounded_server', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None

BOUNDED = _load_bounded()
BOUNDED_LOAD_ERROR = (
    None if BOUNDED is not None else "ERROR: missing frp_bounded_server.py; refusing unbounded server"
)



def _load_health_check():
    candidates = [
        Path(__file__).resolve().parent / 'frp_health_check.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_health_check.py',
        Path('/usr/local/lib/drlink/frp_health_check.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_health_check.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_health_check.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_health_check', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


HC = _load_health_check()


def _load_enrollment_lifecycle():
    candidates = [
        Path(__file__).resolve().parent / 'frp_enrollment_lifecycle.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_enrollment_lifecycle.py',
        Path('/usr/local/lib/drlink/frp_enrollment_lifecycle.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_enrollment_lifecycle.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_enrollment_lifecycle.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_enrollment_lifecycle', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


ELC = _load_enrollment_lifecycle()


def _load_control_locks():
    candidates = [
        Path(__file__).resolve().parent / 'frp_control_locks.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_control_locks.py',
        Path('/usr/local/lib/drlink/frp_control_locks.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_control_locks.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_control_locks.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_control_locks', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise RuntimeError('missing frp_control_locks.py')


CLOCKS = _load_control_locks()


def _load_zero_touch():
    candidates = [
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_zero_touch.py',
        Path('/usr/local/lib/drlink/frp_zero_touch.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_zero_touch.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_zero_touch.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_zero_touch', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


ZT = _load_zero_touch()


def _load_qualified_artifacts():
    candidates = [
        Path(__file__).resolve().parent.parent / 'lib' / 'drlink_qualified_artifacts.py',
        Path('/usr/local/lib/drlink/drlink_qualified_artifacts.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'drlink_qualified_artifacts.py')
        candidates.insert(0, Path(root) / 'lib' / 'drlink_qualified_artifacts.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location(
                'drlink_qualified_artifacts', path
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


QA = _load_qualified_artifacts()


def _load_pki():
    candidates = [
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_pki.py',
        Path('/usr/local/lib/drlink/frp_pki.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_pki.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_pki.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_pki', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


PKI = _load_pki()


def unsupported_registry_message(state=None):
    version = None
    if isinstance(state, dict) and 'schema_version' in state:
        version = state.get('schema_version')
    shown = 1 if version is None else version
    return (
        f'unsupported registry schema version {shown}. '
        'This release requires registry schema version 2. '
        'Back up the existing registry and redeploy/reset it explicitly before continuing.'
    )


class RegistrySchemaError(ValueError):
    pass


class ServiceValidationError(ValueError):
    pass


class PortRangeExhausted(RuntimeError):
    pass


class FileLock:
    """Exclusive filesystem lock. Released automatically on process death."""

    def __init__(self, path):
        self.path = Path(path)
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except Exception:
            os.close(self.fd)
            self.fd = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        return False


def api_error(message, error_class):
    return {'error': str(message), 'error_class': error_class}


def classify_auth_error(error):
    text = str(error or '').lower()
    if 'revoked' in text:
        return 'REVOKED'
    if 'replay' in text:
        return 'REPLAY_REJECTED'
    if 'nonce store full' in text:
        return 'NONCE_STORE_FULL'
    return 'AUTH_FAILED'


def registry_lock_path(registry_file):
    return Path(registry_file).resolve().parent / 'registry.lock'


def _test_before_registry_write(path):
    """Production no-op. Unit tests may replace this symbol."""
    return None


def _test_before_nonce_write(path):
    """Production no-op. Unit tests may replace this symbol to fail nonce persist."""
    return None


def _test_enrollment_failure_point(point):
    """Production no-op. Unit tests may raise to inject AFTER_* failures."""
    return None


def _pair_write_pause_hook():
    """Pause between the two durable writes of an enrollment pair.

    Production no-op unless both hook paths are set. Tests use it to prove a
    concurrent backup cannot observe a half-written pair: the writer signals
    readiness while still holding the control locks and waits for a go file.
    """
    ready = os.environ.get('FRP_ENROLLMENT_PAIR_HOOK_READY', '')
    go = os.environ.get('FRP_ENROLLMENT_PAIR_HOOK_GO', '')
    if not ready or not go:
        return
    Path(ready).write_text('ready\n', encoding='utf-8')
    deadline = time.time() + float(os.environ.get('FRP_ENROLLMENT_PAIR_HOOK_WAIT', '10'))
    while time.time() < deadline:
        if Path(go).is_file():
            return
        time.sleep(0.05)


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def empty_registry():
    return {
        'schema_version': REGISTRY_SCHEMA_VERSION,
        'reserved': [],
        'clients': {},
    }


def load_json(path, default=None):
    p = Path(path)
    if not p.exists():
        if default is None:
            raise FileNotFoundError(path)
        return default
    with p.open('r', encoding='utf-8') as f:
        return json.load(f)


def atomic_write_json(path, data, mode=0o600):
    p = Path(path)
    path_s = str(p)
    if path_s.endswith('mgmt-nonces.json') or path_s.endswith('mgmt-nonces.json.tmp') or p.name.startswith('mgmt-nonces.json.'):
        _test_before_nonce_write(path_s)
    else:
        _test_before_registry_write(path_s)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + '.', suffix='.tmp', dir=str(p.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        try:
            CLOCKS.durable_replace(tmp, p)
        except Exception:
            # Fallback keeps prior semantics on exotic/unsupported filesystems.
            os.replace(tmp, p)
        tmp = None  # durable_replace/replace consumed the temp path
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def read_text(path):
    return Path(path).read_text(encoding='utf-8').strip()


def read_project_version(root=''):
    """Return installed PROJECT_VERSION for health/compatibility checks."""
    candidates = []
    if root:
        candidates.append(Path(root) / 'etc/drlink/version')
    candidates.extend(
        [
            Path('/etc/drlink/version'),
            Path(__file__).resolve().parent.parent / 'VERSION',
        ]
    )
    for path in candidates:
        try:
            present = path.is_file()
        except OSError:
            continue
        if not present:
            continue
        try:
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                key, sep, value = line.partition('=')
                if sep and key.strip() == 'PROJECT_VERSION':
                    return value.strip()
        except OSError:
            continue
    return ''


def parse_project_version(text):
    text = str(text or '').strip()
    parts = []
    for piece in text.split('.'):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) if parts else None


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def hmac_hex(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def unlink_quiet(path):
    try:
        Path(path).unlink()
    except OSError:
        pass


def hash_bootstrap_secret(secret):
    return hashlib.sha256(secret.encode('ascii')).hexdigest()


class BootstrapPathExists(Exception):
    """Derived ticket or enrollment path is already occupied."""


def generate_compact_bootstrap_credential():
    """128-bit CSPRNG capability, unpadded base64url (22 chars)."""
    token = base64.urlsafe_b64encode(
        secrets.token_bytes(COMPACT_CREDENTIAL_BYTES)
    ).decode('ascii').rstrip('=')
    if not COMPACT_CREDENTIAL_RE.fullmatch(token):
        raise RuntimeError('compact bootstrap credential encoding failed')
    return token


def compact_bootstrap_record_id(credential):
    return hash_bootstrap_secret(credential)[:BOOTSTRAP_ID_HEX_LEN]


def short_handle_index_path(bootstrap_dir, handle_id):
    text = str(handle_id or '').lower()
    if len(text) != BOOTSTRAP_ID_HEX_LEN or not HEX_RE.fullmatch(text):
        return None
    return Path(bootstrap_dir) / 'handles' / (text + '.json')


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def _b64url_decode(text):
    raw = str(text or '')
    pad = '=' * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode(raw + pad)


BOOTSTRAP_WRAP_VERSION = 2
BOOTSTRAP_WRAP_AAD = b'bt1-wrap-v2'
BOOTSTRAP_WRAP_KDF_DOMAIN = b'drlink-bt1-wrap-v2'
BOOTSTRAP_WRAP_ENC_INFO = b'bt1-enc'
BOOTSTRAP_WRAP_MAC_INFO = b'bt1-mac'
BOOTSTRAP_WRAP_KEY_NAME = 'bt1-wrap.key'


def _bootstrap_wrap_keys(secret, salt):
    """Domain-separated AES and HMAC keys. PBKDF2 and HMAC are stdlib; AES is OpenSSL."""
    material = str(secret or '').encode('utf-8')
    if not material or not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError('bootstrap wrap secret is unavailable')
    prk = hashlib.pbkdf2_hmac(
        'sha256',
        material,
        BOOTSTRAP_WRAP_KDF_DOMAIN + bytes(salt),
        MGMT.OPENSSL_PBKDF2_ITER,
        dklen=32,
    )
    enc_key = hmac.new(prk, BOOTSTRAP_WRAP_ENC_INFO, hashlib.sha256).digest()
    mac_key = hmac.new(prk, BOOTSTRAP_WRAP_MAC_INFO, hashlib.sha256).digest()
    return enc_key, mac_key


def wrap_bootstrap_ticket(raw_ticket, secret):
    """Encrypt a raw bt1 credential. The JSON value is not the plaintext ticket.

    Encrypt-then-MAC: OpenSSL AES-256-CBC via the management helper, then
    HMAC-SHA256. The MAC is checked before decrypt.
    """
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    enc_key, mac_key = _bootstrap_wrap_keys(secret, salt)
    ciphertext = MGMT._aes256_cbc(str(raw_ticket).encode('utf-8'), enc_key, iv, True)
    mac = hmac.new(
        mac_key, BOOTSTRAP_WRAP_AAD + salt + iv + ciphertext, hashlib.sha256
    ).hexdigest()
    return {
        'v': BOOTSTRAP_WRAP_VERSION,
        'salt': _b64url_encode(salt),
        'iv': _b64url_encode(iv),
        'ct': _b64url_encode(ciphertext),
        'mac': mac,
    }


def unwrap_bootstrap_ticket(blob, secret):
    """Return the raw bt1 credential, or None when the wrap is unusable."""
    if not isinstance(blob, dict):
        return None
    try:
        if int(blob.get('v') or 0) != BOOTSTRAP_WRAP_VERSION:
            return None
        salt = _b64url_decode(blob.get('salt'))
        iv = _b64url_decode(blob.get('iv'))
        ciphertext = _b64url_decode(blob.get('ct'))
        mac = str(blob.get('mac') or '').strip().lower()
        if (
            len(salt) != 16
            or len(iv) != 16
            or not ciphertext
            or len(mac) != 64
            or not HEX_RE.fullmatch(mac)
        ):
            return None
        enc_key, mac_key = _bootstrap_wrap_keys(secret, salt)
        expected = hmac.new(
            mac_key, BOOTSTRAP_WRAP_AAD + salt + iv + ciphertext, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return None
        return MGMT._aes256_cbc(ciphertext, enc_key, iv, False).decode('utf-8')
    except Exception:
        return None


def bootstrap_wrap_matches_record(raw_ticket, record):
    parsed = parse_bootstrap_ticket(raw_ticket)
    if not parsed or not isinstance(record, dict):
        return False
    ticket_id, secret = parsed
    if ticket_id != str(record.get('id') or '').strip().lower():
        return False
    stored = str(record.get('secret_hash') or '')
    if len(stored) != 64 or not HEX_RE.fullmatch(stored):
        return False
    return hmac.compare_digest(hash_bootstrap_secret(secret), stored)


def _read_text_secret(path):
    try:
        return Path(path).read_text(encoding='utf-8').strip()
    except OSError:
        return ''


def bootstrap_wrap_secret(cfg=None, bootstrap_dir=None, create=False):
    """Secret used to encrypt recoverable bt1 material.

    Prefer the server token. When a caller has no token, use a 0600 key file
    outside the ticket JSON so issuance can still recover the credential.
    """
    if isinstance(cfg, dict):
        token_path = str(cfg.get('token_file') or '').strip()
        if token_path:
            secret = _read_text_secret(token_path)
            if secret:
                return secret
    if bootstrap_dir is None and isinstance(cfg, dict):
        bootstrap_dir = cfg.get('bootstrap_dir')
    if not bootstrap_dir:
        return ''
    key_path = Path(bootstrap_dir) / BOOTSTRAP_WRAP_KEY_NAME
    secret = _read_text_secret(key_path)
    if secret or not create:
        return secret
    secret = secrets.token_hex(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(str(key_path), flags, 0o600)
    except FileExistsError:
        return _read_text_secret(key_path)
    try:
        os.write(fd, (secret + '\n').encode('utf-8'))
    finally:
        os.close(fd)
    try:
        os.chmod(str(key_path), 0o600)
    except OSError:
        pass
    return secret


def windows_renderer_inputs_from_cfg(cfg):
    """Non-secret Windows stage-1 inputs. None when the host cannot render yet."""
    if not isinstance(cfg, dict) or ZT is None or PKI is None:
        return None
    allocator = str(cfg.get('allocator_public_url') or '').strip()
    installer = str(cfg.get('windows_client_installer_url') or '').strip()
    ca_path = str(cfg.get('tls_ca_cert') or '').strip()
    if not allocator.lower().startswith('https://') or not installer.lower().startswith('https://'):
        return None
    try:
        if not ca_path or not Path(ca_path).is_file():
            return None
        ca_fp = PKI.fingerprint_from_cert_file(ca_path)
    except OSError:
        return None
    except Exception:
        return None
    if not ca_fp or len(str(ca_fp)) != 64:
        return None
    return {
        'allocator_url': allocator,
        'allocator_ca_sha256': str(ca_fp).strip().lower(),
        'installer_url': installer,
    }


def load_presented_bootstrap(bootstrap_dir, raw, read_record):
    """Resolve a presented bt1 secret or a short-URL handle for GET /i/.

    Returns (ticket_id, record, path, matched). A 22-char handle is lookup
    only. /bootstrap/redeem must not treat it as the bt1 secret.
    """
    text = raw.strip() if isinstance(raw, str) else ''
    parsed = parse_bootstrap_ticket(text)
    if parsed:
        ticket_id, secret = parsed
        provided = hash_bootstrap_secret(secret)
        record, path = read_record(ticket_id)
        stored = BOOTSTRAP_DUMMY_HASH
        if isinstance(record, dict):
            candidate = str(record.get('secret_hash') or '')
            if HEX_RE.fullmatch(candidate) and len(candidate) == 64:
                stored = candidate
        matched = bool(isinstance(record, dict) and hmac.compare_digest(provided, stored))
        return ticket_id, record if matched else None, path, matched
    if COMPACT_CREDENTIAL_RE.fullmatch(text):
        provided = hash_bootstrap_secret(text)
        stored = BOOTSTRAP_DUMMY_HASH
        ticket_id = ''
        index_path = short_handle_index_path(bootstrap_dir, provided[:BOOTSTRAP_ID_HEX_LEN])
        index = None
        if index_path is not None and index_path.is_file():
            try:
                index = load_json(index_path)
            except Exception:
                index = None
        if isinstance(index, dict):
            candidate = str(index.get('handle_hash') or '')
            if HEX_RE.fullmatch(candidate) and len(candidate) == 64:
                stored = candidate
            ticket_id = str(index.get('ticket_id') or '')
        handle_ok = hmac.compare_digest(provided, stored)
        record, path = (None, None)
        if handle_ok and ticket_id:
            record, path = read_record(ticket_id)
        record_hash = ''
        if isinstance(record, dict):
            record_hash = str(record.get('short_handle_hash') or '')
        record_ok = bool(
            HEX_RE.fullmatch(record_hash)
            and len(record_hash) == 64
            and hmac.compare_digest(provided, record_hash)
        )
        matched = bool(handle_ok and record_ok)
        return ticket_id, record if matched else None, path, matched
    hmac.compare_digest(BOOTSTRAP_DUMMY_HASH, BOOTSTRAP_DUMMY_HASH)
    return '', None, None, False


class ZeroTouchCapacityError(RuntimeError):
    """Raised when Zero-Touch issuance would exceed server-side ceilings."""

    def __init__(self, message, *, active_unused=0, max_issuable=0, requested=0):
        super().__init__(message)
        self.active_unused = int(active_unused)
        self.max_issuable = int(max_issuable)
        self.requested = int(requested)


def normalize_zero_touch_ttl(ttl):
    """Normalize Zero-Touch TTL. Default 1h; reject <=0 or >24h."""
    if ttl is None or ttl == '':
        return ZERO_TOUCH_DEFAULT_TTL_SEC
    try:
        seconds = int(ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError('invalid Zero-Touch TTL') from exc
    if seconds <= 0:
        raise ValueError('Zero-Touch TTL must be positive')
    if seconds > ZERO_TOUCH_MAX_TTL_SEC:
        raise ValueError(
            'Zero-Touch TTL must be at most 24h (%s seconds)'
            % ZERO_TOUCH_MAX_TTL_SEC
        )
    return seconds


def bootstrap_ticket_is_active_unused(record, now=None):
    """True when a ticket counts toward the active-unused ceiling."""
    if not isinstance(record, dict):
        return False
    now = int(now if now is not None else time.time())
    if record.get('revoked_at') or record.get('completed_at'):
        return False
    try:
        expires_at = int(record.get('expires_at', 0) or 0)
    except (TypeError, ValueError):
        return False
    if expires_at <= now:
        return False
    return True


def count_active_unused_bootstrap_tickets(bootstrap_dir, now=None):
    """Count valid unused (not consumed/revoked/expired) Zero-Touch tickets."""
    bootstrap_dir = Path(bootstrap_dir)
    now = int(now if now is not None else time.time())
    count = 0
    try:
        entries = list(bootstrap_dir.glob('*.json'))
    except OSError:
        return 0
    for path in entries:
        try:
            record = load_json(path)
        except Exception:
            continue
        if bootstrap_ticket_is_active_unused(record, now=now):
            count += 1
    return count


def max_issuable_zero_touch_tickets(bootstrap_dir, now=None):
    active = count_active_unused_bootstrap_tickets(bootstrap_dir, now=now)
    remaining = ZERO_TOUCH_MAX_ACTIVE_UNUSED - active
    if remaining < 0:
        remaining = 0
    return min(ZERO_TOUCH_MAX_PER_ISSUE, remaining), active


def assert_zero_touch_issuance_capacity(bootstrap_dir, requested, now=None):
    """Fail closed before any issuance when capacity is insufficient."""
    requested = int(requested)
    if requested <= 0:
        raise ValueError('Zero-Touch issuance count must be positive')
    if requested > ZERO_TOUCH_MAX_PER_ISSUE:
        raise ZeroTouchCapacityError(
            'Zero-Touch issuance rejects requests above %s tickets per issue '
            '(requested=%s).'
            % (ZERO_TOUCH_MAX_PER_ISSUE, requested),
            active_unused=count_active_unused_bootstrap_tickets(bootstrap_dir, now=now),
            max_issuable=ZERO_TOUCH_MAX_PER_ISSUE,
            requested=requested,
        )
    max_ok, active = max_issuable_zero_touch_tickets(bootstrap_dir, now=now)
    if requested > max_ok:
        raise ZeroTouchCapacityError(
            'Zero-Touch capacity exceeded.\n'
            'ACTIVE_UNUSED=%s\n'
            'MAX_ACTIVE_UNUSED=%s\n'
            'MAX_ISSUABLE=%s\n'
            'REQUESTED=%s\n'
            'Issued: 0'
            % (active, ZERO_TOUCH_MAX_ACTIVE_UNUSED, max_ok, requested),
            active_unused=active,
            max_issuable=max_ok,
            requested=requested,
        )
    return max_ok, active


def revoke_bootstrap_tickets_by_batch(bootstrap_dir, batch_id, now_iso=None):
    """Revoke unused tickets sharing batch_id. Does not touch enrolled clients."""
    batch_id = str(batch_id or '').strip()
    if not batch_id:
        raise ValueError('batch_id is required')
    bootstrap_dir = Path(bootstrap_dir)
    now_iso = now_iso or utc_now_iso()
    revoked = []
    try:
        entries = list(bootstrap_dir.glob('*.json'))
    except OSError:
        return revoked
    for path in entries:
        try:
            record = load_json(path)
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        if str(record.get('batch_id') or '') != batch_id:
            continue
        if record.get('completed_at') or record.get('revoked_at'):
            continue
        record['revoked_at'] = now_iso
        try:
            atomic_write_json(path, record, mode=0o600)
        except OSError:
            continue
        revoked.append(str(record.get('id') or path.stem))
    return revoked


def parse_bootstrap_ticket(raw):
    """Return (ticket_id, secret) for a bt1 credential, or None.

    The 22-char short-URL handle is not a bt1 secret. Resolve it with
    load_presented_bootstrap. Never raises on malformed input.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        return None
    ticket = raw.strip()
    if not ticket or len(ticket) > BOOTSTRAP_TICKET_MAX_LEN:
        return None
    parts = ticket.split('.')
    if len(parts) != 3:
        return None
    prefix, ticket_id, secret = parts
    if prefix != BOOTSTRAP_TICKET_PREFIX:
        return None
    if len(ticket_id) != BOOTSTRAP_ID_HEX_LEN or len(secret) != BOOTSTRAP_SECRET_HEX_LEN:
        return None
    if not HEX_RE.fullmatch(ticket_id) or not HEX_RE.fullmatch(secret):
        return None
    return ticket_id.lower(), secret.lower()


def bootstrap_dir_from_cfg(cfg):
    configured = str((cfg or {}).get('bootstrap_dir') or '').strip()
    if configured:
        return Path(configured)
    enrollments = str((cfg or {}).get('enrollments_dir') or '').strip()
    if enrollments:
        return Path(enrollments).resolve().parent / 'bootstrap'
    return Path('/var/lib/drlink/bootstrap')


def ensure_secret_dir(path, mode=0o700):
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(p), mode)
    except OSError:
        pass
    return p


def enrollment_file_path(enrollments_dir, enrollment_id):
    if not enrollment_id or any(c not in '0123456789abcdef' for c in enrollment_id.lower()):
        return None
    return Path(enrollments_dir) / (enrollment_id.lower() + '.json')


def bootstrap_file_path(bootstrap_dir, ticket_id):
    if not ticket_id or not HEX_RE.fullmatch(str(ticket_id).lower()):
        return None
    if len(ticket_id) != BOOTSTRAP_ID_HEX_LEN:
        return None
    return Path(bootstrap_dir) / (ticket_id.lower() + '.json')


def cleanup_expired_bootstrap_tickets(
    bootstrap_dir, now=None, keep_id=None, cfg=None, force=False, already_locked=False
):
    """Pair-aware retention cleanup for terminal enrollment metadata.

    Active / in-retention terminal records are preserved. keep_id is accepted
    for call-site compatibility and is unused (cleanup never targets active rows).

    already_locked=True when the caller already holds registry.lock (e.g.
    /bootstrap/redeem). Retention must not reacquire the flock in that case.

    cfg carries the retention policy. Without it there is nothing to enforce, so
    cleanup is skipped rather than run against a substituted default.
    """
    del keep_id
    if ELC is None or not cfg:
        return
    try:
        ELC.maybe_run_retention_cleanup(
            cfg,
            force=force,
            audit_emit=ELC.load_audit_emit(),
            now=now,
            already_locked=already_locked,
        )
    except Exception:
        return


def enrollment_state_dir(enrollments_dir, cfg=None):
    """Directory holding registry.json and the control-state lock files."""
    registry_file = str((cfg or {}).get('registry_file') or '').strip()
    if registry_file:
        return Path(registry_file).resolve().parent
    return Path(enrollments_dir).resolve().parent


def _prepare_bootstrap_ticket_pair(
    services, ttl, note='', label='', batch_id='', windows_inputs=None, wrap_secret=''
):
    """Build enrollment+ticket records, bt1 secret, and display-once short handle.

    The persisted ticket keeps the 256-bit bt1 verifier. The 22-char handle is
    short-URL-only and is not written except as a hash plus a non-secret index.
    """
    services = normalize_services(services)
    ttl = normalize_zero_touch_ttl(ttl)
    note = str(note or '')
    label = str(label or '')
    batch_id = str(batch_id or '').strip()
    enrollment_id = secrets.token_hex(8)
    enroll_secret = secrets.token_hex(32)
    ticket_id = secrets.token_hex(8)
    ticket_secret = secrets.token_hex(32)
    raw_ticket = '%s.%s.%s' % (BOOTSTRAP_TICKET_PREFIX, ticket_id, ticket_secret)
    short_handle = generate_compact_bootstrap_credential()
    if not str(wrap_secret or '').strip():
        raise RuntimeError('bootstrap ticket wrap secret is unavailable')
    now = int(time.time())
    expires_at = now + ttl
    enroll_record = {
        'id': enrollment_id,
        'secret': enroll_secret,
        'created_at': utc_now_iso(),
        'expires_at': expires_at,
        'expires_at_iso': datetime.fromtimestamp(
            expires_at, timezone.utc
        ).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'bound_machine_id': None,
        'used_at': None,
        'note': note,
        'label': label,
        'authorized_services': services,
    }
    ticket_record = {
        'schema': 1,
        'id': ticket_id,
        'secret_hash': hash_bootstrap_secret(ticket_secret),
        'short_handle_hash': hash_bootstrap_secret(short_handle),
        'bt1_wrapped': wrap_bootstrap_ticket(raw_ticket, wrap_secret),
        '_short_handle': short_handle,
        'enrollment_id': enrollment_id,
        'created_at': utc_now_iso(),
        'expires_at': expires_at,
        'bound_machine_id': None,
        'completed_at': None,
        'note': note,
        'label': label,
        'services': services,
        'use_count_max': ZERO_TOUCH_USE_COUNT,
    }
    if batch_id:
        ticket_record['batch_id'] = batch_id
    if windows_inputs and ZT is not None:
        script = ZT.render_short_url_windows_bootstrap_script(
            windows_inputs['allocator_url'],
            windows_inputs['allocator_ca_sha256'],
            raw_ticket,
            windows_inputs['installer_url'],
        )
        ticket_record['windows_renderer'] = {
            'version': 1,
            'allocator_url': windows_inputs['allocator_url'],
            'allocator_ca_sha256': windows_inputs['allocator_ca_sha256'],
            'installer_url': windows_inputs['installer_url'],
            'stage1_sha256': hashlib.sha256(script.encode('utf-8')).hexdigest(),
        }
    return raw_ticket, enroll_record, ticket_record


def _persist_bootstrap_ticket_pair(enrollments_dir, bootstrap_dir, enroll_record, ticket_record):
    """Write enrollment+ticket pair. Caller must hold control locks."""
    public_ticket = {
        key: value
        for key, value in ticket_record.items()
        if not str(key).startswith('_')
    }
    enroll_path = enrollment_file_path(enrollments_dir, enroll_record['id'])
    ticket_path = bootstrap_file_path(bootstrap_dir, public_ticket['id'])
    handle_hash = str(public_ticket.get('short_handle_hash') or '')
    index_path = None
    if HEX_RE.fullmatch(handle_hash) and len(handle_hash) == 64:
        index_path = short_handle_index_path(bootstrap_dir, handle_hash[:BOOTSTRAP_ID_HEX_LEN])
    if enroll_path is None or ticket_path is None or index_path is None:
        raise RuntimeError('failed to allocate bootstrap ticket paths')
    if enroll_path.exists() or ticket_path.exists() or index_path.exists():
        raise BootstrapPathExists('bootstrap ticket path already exists')
    index_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(index_path.parent), 0o700)
    except OSError:
        pass
    try:
        atomic_write_json(enroll_path, enroll_record, mode=0o600)
        try:
            os.chmod(str(enroll_path), 0o600)
        except OSError:
            pass
        _pair_write_pause_hook()
        atomic_write_json(ticket_path, public_ticket, mode=0o600)
        try:
            os.chmod(str(ticket_path), 0o600)
        except OSError:
            pass
        atomic_write_json(
            index_path,
            {'ticket_id': public_ticket['id'], 'handle_hash': handle_hash},
            mode=0o600,
        )
    except Exception:
        unlink_quiet(index_path)
        unlink_quiet(ticket_path)
        unlink_quiet(enroll_path)
        raise
    return enroll_path, ticket_path


def _allocate_and_persist_bootstrap_ticket_pair(
    enrollments_dir,
    bootstrap_dir,
    services,
    ttl,
    note='',
    label='',
    batch_id='',
    windows_inputs=None,
    wrap_secret='',
):
    """Persist one pair, retrying when the ticket or handle path already exists."""
    last = None
    for _attempt in range(BOOTSTRAP_ALLOCATE_ATTEMPTS):
        raw_ticket, enroll_record, ticket_record = _prepare_bootstrap_ticket_pair(
            services,
            ttl,
            note=note,
            label=label,
            batch_id=batch_id,
            windows_inputs=windows_inputs,
            wrap_secret=wrap_secret,
        )
        try:
            _persist_bootstrap_ticket_pair(
                enrollments_dir, bootstrap_dir, enroll_record, ticket_record
            )
            return raw_ticket, enroll_record, ticket_record
        except BootstrapPathExists as exc:
            last = exc
            continue
    raise RuntimeError('failed to allocate a unique bootstrap ticket') from last


def issue_bootstrap_ticket(
    enrollments_dir,
    bootstrap_dir,
    services,
    ttl,
    note='',
    label='',
    cfg=None,
    *,
    batch_id='',
    requested_count=1,
):
    """Create a hashed bootstrap ticket plus a normal enrollment record.

    Does not allocate a public port. Caller must have already validated
    `services` with normalize_services(); re-normalizing here keeps the ticket
    scope byte-identical to what /enroll compares a request against.

    The enrollment record and the bootstrap ticket are one logical pair. Both
    durable writes happen under lifecycle → control-state → registry locks (the
    documented order backup and restore use), so a concurrent backup archives
    either the pre-create state or the complete pair, never one half.

    Retention cleanup uses the caller's server cfg. Callers must pass cfg= to
    get their configured enrollment_retention_days; a cfg synthesized here
    would silently fall back to the 30-day default.

    Capacity ceilings (max 10/issue, max 10 active unused) are enforced under
    the same locks so concurrent issuers cannot bypass them.
    """
    enrollments_dir = Path(enrollments_dir)
    bootstrap_dir = ensure_secret_dir(bootstrap_dir, 0o700)
    try:
        os.chmod(str(enrollments_dir), 0o700)
    except OSError:
        enrollments_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(enrollments_dir), 0o700)
        except OSError:
            pass
    cleanup_cfg = None
    if cfg:
        cleanup_cfg = dict(cfg)
        cleanup_cfg['enrollments_dir'] = str(enrollments_dir)
        cleanup_cfg['bootstrap_dir'] = str(bootstrap_dir)
    state_dir = enrollment_state_dir(enrollments_dir, cfg)
    lock_timeout = float(
        os.environ.get('FRP_ENROLLMENT_LOCK_TIMEOUT')
        or CLOCKS.DEFAULT_TIMEOUT_SEC
    )
    now = int(time.time())
    windows_inputs = windows_renderer_inputs_from_cfg(cfg)
    wrap_secret = bootstrap_wrap_secret(cfg, bootstrap_dir, create=True)
    with CLOCKS.acquire_state_dir_control_locks(state_dir, timeout=lock_timeout):
        cleanup_expired_bootstrap_tickets(
            bootstrap_dir, now, cfg=cleanup_cfg, force=True, already_locked=True
        )
        assert_zero_touch_issuance_capacity(
            bootstrap_dir, int(requested_count or 1), now=now
        )
        return _allocate_and_persist_bootstrap_ticket_pair(
            enrollments_dir,
            bootstrap_dir,
            services,
            ttl,
            note=note,
            label=label,
            batch_id=batch_id,
            windows_inputs=windows_inputs,
            wrap_secret=wrap_secret,
        )


def issue_bootstrap_ticket_batch(
    enrollments_dir,
    bootstrap_dir,
    rows,
    ttl,
    cfg=None,
    *,
    batch_id=None,
):
    """Issue N unique single-use tickets under one capacity reservation.

    rows: list of dicts with keys services, note, label.
    Rejects the entire request (issues 0) when capacity is insufficient.
    """
    rows = list(rows or [])
    count = len(rows)
    if count == 0:
        raise ValueError('Zero-Touch batch is empty')
    ttl = normalize_zero_touch_ttl(ttl)
    batch_id = str(batch_id or secrets.token_hex(8))
    enrollments_dir = Path(enrollments_dir)
    bootstrap_dir = ensure_secret_dir(bootstrap_dir, 0o700)
    try:
        os.chmod(str(enrollments_dir), 0o700)
    except OSError:
        enrollments_dir.mkdir(parents=True, exist_ok=True)
    cleanup_cfg = None
    if cfg:
        cleanup_cfg = dict(cfg)
        cleanup_cfg['enrollments_dir'] = str(enrollments_dir)
        cleanup_cfg['bootstrap_dir'] = str(bootstrap_dir)
    state_dir = enrollment_state_dir(enrollments_dir, cfg)
    lock_timeout = float(
        os.environ.get('FRP_ENROLLMENT_LOCK_TIMEOUT')
        or CLOCKS.DEFAULT_TIMEOUT_SEC
    )
    now = int(time.time())
    windows_inputs = windows_renderer_inputs_from_cfg(cfg)
    wrap_secret = bootstrap_wrap_secret(cfg, bootstrap_dir, create=True)
    issued = []
    created_paths = []
    with CLOCKS.acquire_state_dir_control_locks(state_dir, timeout=lock_timeout):
        cleanup_expired_bootstrap_tickets(
            bootstrap_dir, now, cfg=cleanup_cfg, force=True, already_locked=True
        )
        assert_zero_touch_issuance_capacity(bootstrap_dir, count, now=now)
        try:
            for row in rows:
                raw_ticket, enroll_record, ticket_record = (
                    _allocate_and_persist_bootstrap_ticket_pair(
                        enrollments_dir,
                        bootstrap_dir,
                        row.get('services') or [],
                        ttl,
                        note=row.get('note') or '',
                        label=row.get('label') or '',
                        batch_id=batch_id,
                        windows_inputs=windows_inputs,
                        wrap_secret=wrap_secret,
                    )
                )
                enroll_path = enrollment_file_path(enrollments_dir, enroll_record['id'])
                ticket_path = bootstrap_file_path(bootstrap_dir, ticket_record['id'])
                handle_hash = str(ticket_record.get('short_handle_hash') or '')
                index_path = short_handle_index_path(
                    bootstrap_dir, handle_hash[:BOOTSTRAP_ID_HEX_LEN]
                )
                created_paths.append((enroll_path, ticket_path, index_path))
                issued.append((raw_ticket, enroll_record, ticket_record))
        except Exception:
            for enroll_path, ticket_path, index_path in created_paths:
                unlink_quiet(index_path)
                unlink_quiet(ticket_path)
                unlink_quiet(enroll_path)
            raise
    return batch_id, issued


def port_is_available(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def encrypt_token(token, secret):
    return MGMT.encrypt_token_pbkdf2(token, secret)


def cfg_public_host(cfg):
    """FRP control host: public_ip preferred, then legacy public_host."""
    for key in ('public_ip', 'public_host'):
        value = cfg.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    raise RuntimeError('public_host is not configured')


def cfg_public_hostname(cfg):
    value = cfg.get('public_hostname')
    if value is None:
        return ''
    text = str(value).strip()
    return text


def cfg_bootstrap_hostname(cfg):
    value = cfg.get('bootstrap_hostname')
    if value is None:
        return ''
    return str(value).strip().lower()


SHORT_URL_PATH_RE = re.compile(r'^/i/([^/]+)$')


def redact_allocator_log_path(raw_path):
    """Redact sensitive /i/<ticket> path segments for allocator access logs."""
    text = str(raw_path or '/')
    if ZT is not None:
        return ZT.redact_text(text)
    return re.sub(r'(/i/)[^/?\s#]+', r'\1<redacted>', text, flags=re.IGNORECASE)


def cfg_frp_control_public_port(cfg):
    port = coerce_port(cfg.get('frp_control_public_port'))
    if port is not None:
        return port
    port = coerce_port(cfg.get('control_port'))
    if port is not None:
        return port
    raise RuntimeError('frp_control_public_port is not configured')


def cfg_frp_control_listen_port(cfg):
    port = coerce_port(cfg.get('frp_control_listen_port'))
    if port is not None:
        return port
    port = coerce_port(cfg.get('control_port'))
    if port is not None:
        return port
    return None


def cfg_allocator_listen_port(cfg):
    port = coerce_port(cfg.get('allocator_listen_port'))
    if port is not None:
        return port
    return coerce_port(cfg.get('listen_port'))


def cfg_deployment_mode(cfg):
    raw = str(cfg.get('deployment_mode') or 'direct').strip().lower()
    compact = raw.replace('-', '').replace('_', '')
    if compact in ('single443', 'enterprise', 'enterprisesingle443'):
        return 'single443'
    return 'direct'


def cfg_frp_transport(cfg):
    explicit = str(cfg.get('frp_transport') or '').strip().lower()
    if explicit == 'wss':
        return 'wss'
    if explicit == 'tcp':
        return 'tcp'
    if cfg_deployment_mode(cfg) == 'single443':
        return 'wss'
    return 'tcp'


def coerce_port(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    text = str(value).strip()
    if not text or not re.fullmatch(r'[0-9]+', text):
        return None
    port = int(text)
    if 1 <= port <= 65535:
        return port
    return None


def require_registry_v2(state):
    if not isinstance(state, dict):
        raise RegistrySchemaError(unsupported_registry_message(state))
    version = state.get('schema_version')
    if version != REGISTRY_SCHEMA_VERSION:
        raise RegistrySchemaError(unsupported_registry_message(state))
    clients = state.get('clients', {})
    if clients is None:
        clients = {}
    if not isinstance(clients, dict):
        raise RegistrySchemaError(unsupported_registry_message(state))
    for client in clients.values():
        if not isinstance(client, dict):
            raise RegistrySchemaError(unsupported_registry_message(state))
        if 'ssh_port' in client or 'https_port' in client:
            raise RegistrySchemaError(
                'unsupported registry schema version 2. '
                'Legacy SSH/HTTPS fields are present. '
                'Back up the existing registry and redeploy/reset it explicitly before continuing.'
            )
        services = client.get('services', {})
        if services is None:
            services = {}
        if not isinstance(services, dict):
            raise RegistrySchemaError(unsupported_registry_message(state))
    reserved = state.get('reserved', [])
    if reserved is None:
        reserved = []
    if not isinstance(reserved, list):
        raise RegistrySchemaError(unsupported_registry_message(state))
    return state


def _load_infrastructure_ports():
    candidates = [
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_infrastructure_ports.py',
        Path('/usr/local/lib/drlink/frp_infrastructure_ports.py'),
    ]
    root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    if root:
        candidates.insert(0, Path(root) / 'usr/local/lib/drlink' / 'frp_infrastructure_ports.py')
        candidates.insert(0, Path(root) / 'lib' / 'frp_infrastructure_ports.py')
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_infrastructure_ports', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


INFRA = _load_infrastructure_ports()


def infrastructure_protected_ports(cfg):
    """Canonical infrastructure ports that must never be allocated as services."""
    if INFRA is not None:
        return set(INFRA.infrastructure_ports(cfg))
    protected = set()
    for port in (
        cfg_allocator_listen_port(cfg) if cfg else None,
        cfg_frp_control_listen_port(cfg) if cfg else None,
        coerce_port((cfg or {}).get('listen_port')) if cfg else None,
        coerce_port((cfg or {}).get('egress_listen_port')) if cfg else None,
    ):
        if port is not None:
            protected.add(port)
    if cfg:
        addr = str(cfg.get('access_plugin_addr') or '127.0.0.1:6101').strip()
        if ':' in addr:
            port = coerce_port(addr.rsplit(':', 1)[-1])
            if port is not None:
                protected.add(port)
    return protected


def validate_registry_invariants(state, cfg=None):
    """Fail closed on severe registry corruption. Do not silently repair."""
    state = require_registry_v2(state)
    # Group structure / membership referential integrity (canonical helper
    # shared with doctor, restore preflight, and the group tooling).
    creg = _load_client_registry_for_invariants()
    if creg is None:
        raise RegistrySchemaError(
            'REGISTRY_INVALID: frp_client_registry.py is unavailable'
        )
    try:
        creg.validate_group_invariants(state)
    except creg.GroupInvariantError as exc:
        raise RegistrySchemaError('REGISTRY_INVALID: %s' % exc) from exc
    seen_ports = {}
    port_start = None
    port_end = None
    protected = set()
    if cfg:
        try:
            port_start = int(cfg.get('port_start'))
            port_end = int(cfg.get('port_end'))
        except (TypeError, ValueError):
            port_start = None
            port_end = None
        protected = infrastructure_protected_ports(cfg)
    for item in state.get('reserved') or []:
        port = coerce_port(item)
        if port is not None:
            seen_ports[port] = ('reserved', None)
    for mid, client in (state.get('clients') or {}).items():
        if not isinstance(client, dict):
            raise RegistrySchemaError('REGISTRY_INVALID: client record is not an object')
        status = client.get('mgmt_status')
        if status is not None and status not in ('enrolled', 'legacy', 'revoked'):
            raise RegistrySchemaError('REGISTRY_INVALID: invalid management identity status')
        services = client.get('services') or {}
        if not isinstance(services, dict):
            raise RegistrySchemaError('REGISTRY_INVALID: client services must be a map')
        seen_ids = set()
        for sid, svc in services.items():
            key = str(sid).strip().lower()
            if key in seen_ids:
                raise RegistrySchemaError('REGISTRY_INVALID: duplicate service id for client')
            seen_ids.add(key)
            if not isinstance(svc, dict):
                raise RegistrySchemaError('REGISTRY_INVALID: service record is not an object')
            port = coerce_port(svc.get('remote_port'))
            if port is None:
                continue
            # reserved[] is the held-port bookkeeping list and commonly overlaps
            # active service remote_ports. Collision is only when another
            # non-reserved owner already claims the port (doctor parity).
            if port in seen_ports and seen_ports[port][0] != 'reserved':
                raise RegistrySchemaError('REGISTRY_INVALID: duplicate public port ownership')
            seen_ports[port] = (mid, key)
            in_service_range = (
                port_start is not None
                and port_end is not None
                and port_start <= port <= port_end
            )
            in_fixed_range = False
            if INFRA is not None:
                try:
                    in_fixed_range = bool(INFRA.is_tcp_relay_port(port, cfg))
                except Exception:
                    in_fixed_range = False
            elif 6200 <= port <= 6299:
                in_fixed_range = True
            # Published service pool or dedicated Fixed TCP pool (including
            # legacy untagged Custom TCP records that already hold 6200-6299).
            if not (in_service_range or in_fixed_range):
                if port_start is not None and port_end is not None:
                    raise RegistrySchemaError(
                        'REGISTRY_INVALID: allocated port outside configured range'
                    )
            if port in protected:
                raise RegistrySchemaError('REGISTRY_INVALID: allocated port collides with a reserved control port')
    # Derived FRP proxy names must be unique (hostname + machine_id[:8] + service).
    # Last-write-wins map assignment would silently mis-authorize.
    acl = _load_access_control_for_invariants()
    if acl is not None:
        try:
            acl.validate_proxy_name_uniqueness(state)
        except acl.AccessError as exc:
            raise RegistrySchemaError('REGISTRY_INVALID: %s' % exc) from exc
    return state


_ACL_FOR_INVARIANTS = None
_CREG_FOR_INVARIANTS = None


def _load_client_registry_for_invariants():
    global _CREG_FOR_INVARIANTS
    if _CREG_FOR_INVARIANTS is not None:
        return _CREG_FOR_INVARIANTS
    for path in (
        Path(__file__).resolve().parent / 'frp_client_registry.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_client_registry.py',
        Path('/usr/local/lib/drlink/frp_client_registry.py'),
    ):
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_client_registry', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _CREG_FOR_INVARIANTS = mod
            return mod
    return None


def _load_access_control_for_invariants():
    global _ACL_FOR_INVARIANTS
    if _ACL_FOR_INVARIANTS is not None:
        return _ACL_FOR_INVARIANTS
    for path in (
        Path(__file__).resolve().parent / 'frp_access_control.py',
        Path(__file__).resolve().parent.parent / 'lib' / 'frp_access_control.py',
        Path('/usr/local/lib/drlink/frp_access_control.py'),
    ):
        if path.is_file():
            spec = importlib.util.spec_from_file_location('frp_access_control', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _ACL_FOR_INVARIANTS = mod
            return mod
    return None


def used_ports_from_state(state):
    used = set()
    for item in state.get('reserved') or []:
        port = coerce_port(item)
        if port is not None:
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
            if port is not None:
                used.add(port)
    return used


def valid_local_ip(value):
    text = str(value).strip()
    if not text or len(text) > MAX_HOST_LEN:
        return False
    if any(c in text for c in ' \t\r\n/\\;|&$`\'"<>'):
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    if text.lower() == 'localhost':
        return True
    if re.fullmatch(r'[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?', text):
        return True
    return False


def normalize_service(raw):
    if not isinstance(raw, dict):
        raise ServiceValidationError('each service must be an object')

    sid = str(raw.get('id', '')).strip().lower()
    if not sid:
        raise ServiceValidationError('service id is required')
    if not SERVICE_ID_RE.fullmatch(sid):
        raise ServiceValidationError(
            'invalid service id; use [a-z0-9][a-z0-9._-]{0,31}'
        )

    protocol = str(raw.get('protocol', 'tcp') or 'tcp').strip().lower()
    if protocol not in ALLOWED_PROTOCOLS:
        raise ServiceValidationError('only tcp services are supported')

    preset = str(raw.get('preset', 'custom') or 'custom').strip().lower()
    if preset not in ALLOWED_PRESETS:
        raise ServiceValidationError('invalid service preset')

    default_name = {
        'ssh': 'SSH',
        'http': 'HTTP',
        'https': 'HTTPS',
    }.get(preset, sid)
    name = str(raw.get('name', '') or default_name).strip() or default_name
    try:
        name = CREG.validate_text_field(name, 'service name', MAX_NAME_LEN, required=True)
    except ValueError as exc:
        raise ServiceValidationError(str(exc))

    local_ip = str(raw.get('local_ip', '') or '').strip()
    if not local_ip:
        raise ServiceValidationError('local_ip is required')
    if not valid_local_ip(local_ip):
        raise ServiceValidationError('invalid local_ip')

    local_port = coerce_port(raw.get('local_port'))
    if local_port is None:
        raise ServiceValidationError('invalid local_port; must be an integer 1-65535')

    service = {
        'id': sid,
        'name': name,
        'protocol': 'tcp',
        'local_ip': local_ip,
        'local_port': local_port,
        'preset': preset,
    }
    if preset == 'ssh':
        ssh_user = str(raw.get('ssh_user', '') or '').strip()
        if ssh_user:
            if not re.fullmatch(r'[A-Za-z0-9._@-]{1,32}', ssh_user):
                raise ServiceValidationError('invalid ssh_user')
            service['ssh_user'] = ssh_user
        # ssh_user is optional connection-example metadata; enrollment does not require it.
    if 'health_check' in raw:
        if HC is None:
            raise ServiceValidationError('health_check helpers unavailable')
        try:
            HC.copy_health_check(raw, service)
        except HC.HealthCheckError as exc:
            raise ServiceValidationError(str(exc)) from exc
    return service


def normalize_services(raw_services):
    if raw_services is None:
        raise ServiceValidationError('services is required')
    if not isinstance(raw_services, list):
        raise ServiceValidationError('services must be a list')
    if len(raw_services) > MAX_SERVICES:
        raise ServiceValidationError('too many services in one enrollment request')

    normalized = []
    seen = set()
    for item in raw_services:
        service = normalize_service(item)
        if service['id'] in seen:
            raise ServiceValidationError(f'duplicate service id: {service["id"]}')
        seen.add(service['id'])
        normalized.append(service)
    return normalized


SERVICE_SCOPE_FIELDS = (
    'id',
    'name',
    'protocol',
    'local_ip',
    'local_port',
    'preset',
    'ssh_user',
    'health_check',
)


def service_scope_key(service):
    """Canonical comparable form of one service for authorization scope checks."""
    if not isinstance(service, dict):
        return None
    canonical = {
        field: service[field]
        for field in SERVICE_SCOPE_FIELDS
        if field in service
    }
    return canonical_json(canonical)


def services_match_authorized(requested, authorized):
    """Exact (order-independent) match of requested services against ticket scope."""
    if not isinstance(requested, list) or not isinstance(authorized, list):
        return False
    if len(requested) != len(authorized):
        return False
    want = {}
    for svc in authorized:
        key = service_scope_key(svc)
        if key is None:
            return False
        sid = str(svc.get('id', ''))
        if sid in want:
            return False
        want[sid] = key
    got = {}
    for svc in requested:
        key = service_scope_key(svc)
        if key is None:
            return False
        sid = str(svc.get('id', ''))
        if sid in got:
            return False
        got[sid] = key
    return got == want


class Allocator:
    def __init__(self, config_path):
        self.config_path = config_path
        self._cfg_mtime_ns = None
        self.cfg = {}
        self._apply_config(load_json(config_path), force_paths=True)
        self.enrollments_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.enrollments_dir), 0o700)
        except OSError:
            pass
        ensure_secret_dir(self.bootstrap_dir, 0o700)

    def _config_mtime_ns(self):
        try:
            return Path(self.config_path).stat().st_mtime_ns
        except OSError:
            return None

    def _apply_config(self, cfg, force_paths=False):
        """Apply config dict. Path fields are sticky unless force_paths=True."""
        if not isinstance(cfg, dict):
            raise TypeError('config must be a JSON object')
        if force_paths or not self.cfg:
            self.registry_file = cfg['registry_file']
            self.enrollments_dir = Path(cfg['enrollments_dir'])
            self.bootstrap_dir = bootstrap_dir_from_cfg(cfg)
            self.token_file = cfg['token_file']
            self.nonce_file = Path(self.registry_file).resolve().parent / 'mgmt-nonces.json'
        self.cfg = cfg
        self._cfg_mtime_ns = self._config_mtime_ns()

    def reload_cfg_if_changed(self):
        """Refresh in-memory config when config.json changes on disk.

        frpctl set / installer-url tools update disk without restarting the
        allocator. Short-URL scripts and advertised endpoints must see the
        latest bootstrap_hostname / client_installer_url without a restart.
        """
        mtime_ns = self._config_mtime_ns()
        if mtime_ns is None or mtime_ns == self._cfg_mtime_ns:
            return False
        try:
            cfg = load_json(self.config_path)
        except (OSError, json.JSONDecodeError, TypeError):
            return False
        self._apply_config(cfg, force_paths=False)
        return True

    def registry_lock(self):
        return FileLock(registry_lock_path(self.registry_file))

    def registry_present(self):
        return Path(self.registry_file).exists()

    def load_registry(self):
        """Load derived enrollment inventory projection.

        Missing file is corruption for allocator transport (rebuild from
        SQLite / re-enroll). The file is not policy authority.
        """
        path = Path(self.registry_file)
        if not path.exists():
            legacy = path.parent.parent / 'registry.json'
            if path.name == 'client-inventory.json' and legacy.is_file():
                path.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy2(legacy, path)
        if not Path(self.registry_file).exists():
            raise RegistrySchemaError(
                'client inventory projection is missing (rebuild from SQLite control plane)'
            )
        try:
            state = load_json(self.registry_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistrySchemaError('unable to read enrollment inventory projection') from exc
        require_registry_v2(state)
        return validate_registry_invariants(state, self.cfg)

    def save_registry(self, state):
        state = dict(state)
        state['schema_version'] = REGISTRY_SCHEMA_VERSION
        require_registry_v2(state)
        validate_registry_invariants(state, self.cfg)
        Path(self.registry_file).parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.registry_file, state)

    def used_ports(self, state):
        return used_ports_from_state(state)

    def protected_ports(self):
        return infrastructure_protected_ports(self.cfg)

    def allocate_port(self, used, *, start=None, end=None):
        protected = self.protected_ports()
        start = int(self.cfg['port_start'] if start is None else start)
        end = int(self.cfg['port_end'] if end is None else end)
        for port in range(start, end + 1):
            if port in used or port in protected:
                continue
            if not port_is_available(port):
                continue
            return port
        raise PortRangeExhausted('No available FRP service ports')

    def pool_port_range(self, pool_class):
        """Return (start, end) for normal FRP services or Fixed TCP Remote Services."""
        if str(pool_class or '').strip().lower() == 'fixed-tcp':
            if INFRA is not None:
                return INFRA.tcp_relay_port_range(self.cfg)
            return 6200, 6299
        return int(self.cfg['port_start']), int(self.cfg['port_end'])

    def reserve_remote_service_endpoint(
        self,
        machine_id,
        service_name,
        pool_class,
        *,
        local_ip='127.0.0.1',
        local_port=22,
        preserve_port=None,
        proxy_id=None,
        extra_used=None,
    ):
        """Authoritatively allocate/reserve a Remote Service endpoint in the registry.

        Uses the same used_ports / protected_ports / port_is_available path as
        enrollment allocation. Projects the reservation onto the client service map.
        """
        from drlink_v24_runtime import remote_service_proxy_id

        sid = proxy_id or remote_service_proxy_id(service_name)
        pool = 'fixed-tcp' if str(pool_class or '').strip().lower() == 'fixed-tcp' else 'normal'
        with LOCK:
            with self.registry_lock():
                state = self.load_registry()
                clients = state.setdefault('clients', {})
                client = clients.get(machine_id)
                if not isinstance(client, dict):
                    raise RegistrySchemaError('unknown client identity for endpoint reservation')
                if not isinstance(client.get('services'), dict):
                    client['services'] = {}
                services = client['services']
                used = self.used_ports(state)
                if extra_used:
                    for item in extra_used:
                        port = coerce_port(item)
                        if port is not None:
                            used.add(port)
                # Ports held only in reserved[] remain blocked.
                for item in state.get('reserved') or []:
                    port = coerce_port(item)
                    if port is not None:
                        used.add(port)

                previous = services.get(sid) if isinstance(services.get(sid), dict) else {}
                remote_port = coerce_port(preserve_port)
                if remote_port is None:
                    remote_port = coerce_port(previous.get('remote_port'))
                start, end = self.pool_port_range(pool)
                if remote_port is not None:
                    # Reuse only when still free or already owned by this proxy id.
                    owner = None
                    for mid, other in (state.get('clients') or {}).items():
                        for osid, svc in ((other.get('services') or {}).items()):
                            if coerce_port((svc or {}).get('remote_port')) == remote_port:
                                owner = (mid, osid)
                                break
                        if owner:
                            break
                    if owner and owner != (machine_id, sid):
                        remote_port = None
                    elif remote_port in self.protected_ports():
                        remote_port = None
                    elif remote_port < start or remote_port > end:
                        remote_port = None
                    elif remote_port in used and owner != (machine_id, sid):
                        remote_port = None
                    elif owner != (machine_id, sid) and not port_is_available(remote_port):
                        remote_port = None
                if remote_port is None:
                    # Exclude our previous port from "used" so allocate can reclaim it.
                    prev_port = coerce_port(previous.get('remote_port'))
                    alloc_used = set(used)
                    if prev_port is not None:
                        alloc_used.discard(prev_port)
                    remote_port = self.allocate_port(alloc_used, start=start, end=end)
                    used.add(remote_port)

                stored = {
                    'name': str(service_name),
                    'protocol': 'tcp',
                    'local_ip': str(local_ip or '127.0.0.1'),
                    'local_port': int(local_port),
                    'remote_port': int(remote_port),
                    'preset': 'custom',
                    'enabled': True,
                    'v24_remote_service': True,
                    'pool_class': pool,
                }
                services[sid] = stored
                # Keep reserved[] in sync for bookkeeping consumers.
                reserved = list(state.get('reserved') or [])
                if int(remote_port) not in [coerce_port(x) for x in reserved]:
                    reserved.append(int(remote_port))
                    state['reserved'] = reserved
                self.save_registry(state)
                # Mirror legacy registry.json when the live inventory path differs.
                try:
                    live = Path(self.registry_file).resolve()
                    legacy = live.parent.parent / 'registry.json'
                    if legacy != live and legacy.parent.is_dir():
                        atomic_write_json(str(legacy), state)
                except OSError:
                    pass
                return {
                    'proxy_id': sid,
                    'remote_port': int(remote_port),
                    'pool_class': pool,
                }

    def release_remote_service_endpoint(self, machine_id, service_name, *, proxy_id=None):
        """Release a v2.4 Remote Service endpoint from the authoritative registry."""
        from drlink_v24_runtime import remote_service_proxy_id

        sid = proxy_id or remote_service_proxy_id(service_name)
        with LOCK:
            with self.registry_lock():
                state = self.load_registry()
                clients = state.setdefault('clients', {})
                client = clients.get(machine_id)
                if not isinstance(client, dict):
                    return {'released_port': None, 'proxy_id': sid}
                services = client.get('services') or {}
                if not isinstance(services, dict):
                    return {'released_port': None, 'proxy_id': sid}
                prev = services.pop(sid, None)
                released = coerce_port((prev or {}).get('remote_port')) if isinstance(prev, dict) else None
                # Drop from reserved[] only when no other owner still uses the port.
                if released is not None:
                    still_used = False
                    for other in (state.get('clients') or {}).values():
                        for svc in ((other.get('services') or {}).values()):
                            if coerce_port((svc or {}).get('remote_port')) == released:
                                still_used = True
                                break
                        if still_used:
                            break
                    if not still_used:
                        reserved = []
                        for item in state.get('reserved') or []:
                            if coerce_port(item) != released:
                                reserved.append(item)
                        state['reserved'] = reserved
                client['services'] = services
                self.save_registry(state)
                try:
                    live = Path(self.registry_file).resolve()
                    legacy = live.parent.parent / 'registry.json'
                    if legacy != live and legacy.parent.is_dir():
                        atomic_write_json(str(legacy), state)
                except OSError:
                    pass
                return {'released_port': released, 'proxy_id': sid}

    def enrollment_path(self, enrollment_id):
        if not enrollment_id or any(c not in '0123456789abcdef' for c in enrollment_id.lower()):
            return None
        return self.enrollments_dir / f'{enrollment_id.lower()}.json'

    def load_enrollment(self, enrollment_id):
        path = self.enrollment_path(enrollment_id)
        if path is None or not path.exists():
            return None, path
        return load_json(path), path

    def save_enrollment(self, path, record):
        atomic_write_json(path, record)

    def bootstrap_path(self, ticket_id):
        return bootstrap_file_path(self.bootstrap_dir, ticket_id)

    def load_bootstrap(self, ticket_id):
        path = self.bootstrap_path(ticket_id)
        if path is None or not path.exists():
            return None, path
        try:
            return load_json(path), path
        except (OSError, json.JSONDecodeError):
            return None, path

    def save_bootstrap(self, path, record):
        atomic_write_json(path, record, mode=0o600)

    def cleanup_expired_bootstrap_tickets(
        self, now=None, keep_id=None, force=False, already_locked=False
    ):
        cleanup_expired_bootstrap_tickets(
            self.bootstrap_dir,
            now,
            keep_id=keep_id,
            cfg=self.cfg,
            force=force,
            already_locked=already_locked,
        )

    def issue_bootstrap_ticket(self, services, ttl, note='', label='', *, batch_id='', requested_count=1):
        ensure_secret_dir(self.bootstrap_dir, 0o700)
        return issue_bootstrap_ticket(
            self.enrollments_dir,
            self.bootstrap_dir,
            services,
            ttl,
            note,
            label=label,
            cfg=self.cfg,
            batch_id=batch_id,
            requested_count=requested_count,
        )

    def issue_bootstrap_ticket_batch(self, rows, ttl, *, batch_id=None):
        ensure_secret_dir(self.bootstrap_dir, 0o700)
        return issue_bootstrap_ticket_batch(
            self.enrollments_dir,
            self.bootstrap_dir,
            rows,
            ttl,
            cfg=self.cfg,
            batch_id=batch_id,
        )

    def count_active_unused_bootstrap_tickets(self, now=None):
        return count_active_unused_bootstrap_tickets(self.bootstrap_dir, now=now)

    def max_issuable_zero_touch_tickets(self, now=None):
        return max_issuable_zero_touch_tickets(self.bootstrap_dir, now=now)

    def revoke_bootstrap_tickets_by_batch(self, batch_id):
        return revoke_bootstrap_tickets_by_batch(self.bootstrap_dir, batch_id)

    def _invalid_ticket_response(self):
        return 403, api_error('bootstrap ticket is invalid', 'BOOTSTRAP_TICKET_INVALID')

    def short_url_bootstrap_available(self, raw_ticket):
        """Return True when GET /i/<ticket> may emit a bootstrap script.

        Read-only: never binds machine ID, never sets completed_at, never
        mutates enrollment/bootstrap records.
        """
        _ticket_id, record, _path, matched = load_presented_bootstrap(
            self.bootstrap_dir,
            raw_ticket if isinstance(raw_ticket, str) else '',
            self.load_bootstrap,
        )
        if not matched or not isinstance(record, dict):
            return False
        now = int(time.time())
        try:
            expires_at = int(record.get('expires_at', 0))
        except (TypeError, ValueError):
            expires_at = 0
        if now > expires_at:
            return False
        if record.get('revoked_at') or record.get('completed_at'):
            return False
        return True

    def _credential_for_stage1(self, presented):
        """Internal bt1 embedded in a served stage-1 script.

        New records recover it from bt1_wrapped. Legacy records use the
        presented bt1. A short handle is never the stage-1 credential.
        """
        _ticket_id, record, _path, matched = load_presented_bootstrap(
            self.bootstrap_dir,
            presented if isinstance(presented, str) else '',
            self.load_bootstrap,
        )
        if not matched or not isinstance(record, dict):
            return None
        if isinstance(record.get('bt1_wrapped'), dict):
            raw = unwrap_bootstrap_ticket(
                record.get('bt1_wrapped'),
                bootstrap_wrap_secret(
                    {'token_file': getattr(self, 'token_file', '')},
                    self.bootstrap_dir,
                    create=False,
                ),
            )
            if not bootstrap_wrap_matches_record(raw, record):
                return None
            return raw
        parsed = parse_bootstrap_ticket(presented if isinstance(presented, str) else '')
        if parsed and parsed[0] == str(record.get('id') or '').strip().lower():
            return presented.strip()
        return None

    def build_short_url_script(self, raw_ticket, platform='linux'):
        """Build the generic short-URL bootstrap script, or None on failure."""
        if ZT is None or PKI is None:
            return None
        credential = self._credential_for_stage1(raw_ticket)
        if not credential:
            return None
        if platform == 'windows':
            frozen = self._frozen_windows_stage1(raw_ticket, credential)
            if frozen is not False:
                return frozen
        self.reload_cfg_if_changed()
        allocator = str(self.cfg.get('allocator_public_url') or '').strip()
        if platform == 'windows':
            installer = str(
                self.cfg.get('windows_client_installer_url') or ''
            ).strip()
        else:
            installer = str(self.cfg.get('client_installer_url') or '').strip()
        ca_path = str(self.cfg.get('tls_ca_cert') or '').strip()
        if not allocator.lower().startswith('https://'):
            return None
        if not installer.lower().startswith('https://'):
            return None
        if not ca_path or not Path(ca_path).is_file():
            return None
        try:
            ca_fp = PKI.fingerprint_from_cert_file(ca_path)
        except Exception:
            return None
        if not ca_fp:
            return None
        try:
            if platform == 'windows':
                return ZT.render_short_url_windows_bootstrap_script(
                    allocator, ca_fp, credential, installer
                )
            return ZT.render_short_url_bootstrap_script(
                allocator, ca_fp, credential, installer
            )
        except ValueError:
            return None

    def _frozen_windows_stage1(self, raw_ticket, credential):
        """Replay a frozen Windows stage-1 script.

        Returns the verified script, None to fail closed, or False when the
        record has no frozen renderer and the dynamic path may be used.
        The script embeds the recovered internal bt1, not the short handle.
        """
        _ticket_id, record, _path, matched = load_presented_bootstrap(
            self.bootstrap_dir,
            raw_ticket if isinstance(raw_ticket, str) else '',
            self.load_bootstrap,
        )
        if not matched or not isinstance(record, dict):
            return None
        renderer = record.get('windows_renderer')
        if not isinstance(renderer, dict):
            return False
        try:
            version = int(renderer.get('version') or 0)
        except (TypeError, ValueError):
            return None
        if version != 1 or ZT is None or not credential:
            return None
        try:
            script = ZT.render_short_url_windows_bootstrap_script(
                str(renderer.get('allocator_url') or ''),
                str(renderer.get('allocator_ca_sha256') or ''),
                credential,
                str(renderer.get('installer_url') or ''),
            )
        except ValueError:
            return None
        digest = hashlib.sha256(script.encode('utf-8')).hexdigest()
        stored = str(renderer.get('stage1_sha256') or '')
        if len(stored) != 64 or not hmac.compare_digest(digest, stored.lower()):
            return None
        return script

    def redeem_bootstrap(self, body):
        """Bind a bootstrap ticket to the first machine and return enrollment data."""
        try:
            payload = json.loads(body.decode())
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            return 400, api_error('invalid JSON', 'ZERO_TOUCH_INPUT_INVALID')
        if not isinstance(payload, dict):
            return 400, api_error('invalid JSON', 'ZERO_TOUCH_INPUT_INVALID')

        raw_ticket = payload.get('ticket')
        if raw_ticket is None:
            raw_ticket = payload.get('bootstrap_ticket')
        presented = raw_ticket if isinstance(raw_ticket, str) else ''
        machine_id = str(payload.get('machine_id', '') or '').strip()
        hostname = str(payload.get('hostname', '') or '').strip()
        if MID is not None:
            try:
                machine_id = MID.validate_machine_id(machine_id, required=True)
            except MID.MachineIdError as exc:
                code = 'ZERO_TOUCH_INPUT_INVALID'
                return 400, api_error(str(exc), code)
        else:
            if not machine_id:
                return 400, api_error('machine_id is required', 'ZERO_TOUCH_INPUT_INVALID')
            if len(machine_id) > MACHINE_ID_MAX_LEN or any(c in machine_id for c in '\r\n/\\'):
                return 400, api_error('invalid machine_id', 'ZERO_TOUCH_INPUT_INVALID')
        try:
            hostname = CREG.validate_hostname(hostname)
        except ValueError:
            return 400, api_error('invalid hostname', 'ZERO_TOUCH_INPUT_INVALID')

        parsed = parse_bootstrap_ticket(presented)
        if not parsed:
            hmac.compare_digest(BOOTSTRAP_DUMMY_HASH, BOOTSTRAP_DUMMY_HASH)
        try:
            with LOCK:
                with self.registry_lock():
                    ticket_id = parsed[0] if parsed else ''
                    # Retention must not reacquire registry.lock (nested flock deadlock).
                    self.cleanup_expired_bootstrap_tickets(
                        keep_id=ticket_id, force=True, already_locked=True
                    )
                    record = None
                    path = None
                    stored_hash = BOOTSTRAP_DUMMY_HASH
                    provided_hash = BOOTSTRAP_DUMMY_HASH
                    if parsed:
                        ticket_id, ticket_secret = parsed
                        provided_hash = hash_bootstrap_secret(ticket_secret)
                        record, path = self.load_bootstrap(ticket_id)
                        if isinstance(record, dict):
                            candidate = str(record.get('secret_hash') or '')
                            if HEX_RE.fullmatch(candidate) and len(candidate) == 64:
                                stored_hash = candidate
                    if not parsed or not hmac.compare_digest(provided_hash, stored_hash):
                        return self._invalid_ticket_response()
                    if not isinstance(record, dict):
                        return self._invalid_ticket_response()

                    now = int(time.time())
                    try:
                        expires_at = int(record.get('expires_at', 0))
                    except (TypeError, ValueError):
                        expires_at = 0
                    if now > expires_at:
                        return 410, api_error(
                            'bootstrap ticket has expired',
                            'BOOTSTRAP_TICKET_EXPIRED',
                        )

                    if record.get('revoked_at'):
                        return 403, api_error(
                            'bootstrap ticket has been revoked',
                            'BOOTSTRAP_TICKET_REVOKED',
                        )

                    if record.get('completed_at'):
                        return 409, api_error(
                            'bootstrap ticket has already completed enrollment',
                            'BOOTSTRAP_TICKET_USED',
                        )

                    bound = record.get('bound_machine_id')
                    if bound and bound != machine_id:
                        return 409, api_error(
                            'bootstrap ticket is bound to another machine',
                            'BOOTSTRAP_TICKET_BOUND',
                        )

                    enrollment_id = str(record.get('enrollment_id') or '')
                    enroll_record, enroll_path = self.load_enrollment(enrollment_id)
                    if not enroll_record:
                        return self._invalid_ticket_response()
                    try:
                        enroll_expires = int(enroll_record.get('expires_at', 0))
                    except (TypeError, ValueError):
                        enroll_expires = 0
                    if now > enroll_expires:
                        return 410, api_error(
                            'bootstrap ticket has expired',
                            'BOOTSTRAP_TICKET_EXPIRED',
                        )

                    try:
                        services = normalize_services(record.get('services'))
                    except ServiceValidationError:
                        return self._invalid_ticket_response()

                    if not bound:
                        record['bound_machine_id'] = machine_id
                        self.save_bootstrap(path, record)

                    enroll_secret = str(enroll_record.get('secret') or '')
                    if not enroll_secret:
                        return self._invalid_ticket_response()
                    enrollment_code = '%s.%s' % (
                        str(enroll_record.get('id') or enrollment_id),
                        enroll_secret,
                    )
                    return 200, {
                        'enrollment_code': enrollment_code,
                        'services': services,
                        'note': str(record.get('note') or ''),
                    }
        except RegistrySchemaError:
            return 500, api_error(
                'registry schema is invalid', 'REGISTRY_INVALID'
            )
        except OSError:
            return 500, api_error(
                'failed to persist bootstrap ticket', 'SERVER_MUTATION_FAILED'
            )

    def complete_bootstrap_for_enrollment(self, enrollment_id, machine_id):
        """Mark the matching bootstrap ticket completed/consumed after enrollment.

        Same-machine redeem remains allowed until this runs. After
        completed_at is set, further redeem attempts fail with
        BOOTSTRAP_TICKET_USED.

        Returns True when the ticket is consumed, already consumed, or no
        matching bootstrap ticket exists (manual enrollment). Returns False
        when a matching ticket exists but completion could not be persisted.
        Callers must fail closed on False so enrollment success never leaves
        a reusable ticket.
        """
        if not enrollment_id:
            return True
        try:
            entries = list(self.bootstrap_dir.glob('*.json'))
        except OSError:
            return False
        now_iso = utc_now_iso()
        for path in entries:
            try:
                record = load_json(path)
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            if str(record.get('enrollment_id') or '') != str(enrollment_id):
                continue
            bound = record.get('bound_machine_id')
            if bound and bound != machine_id:
                continue
            if record.get('completed_at'):
                return True
            record['completed_at'] = now_iso
            if not bound:
                record['bound_machine_id'] = machine_id
            try:
                self.save_bootstrap(path, record)
            except OSError:
                return False
            return True
        return True

    def cleanup_expired_enrollments(self):
        now = int(time.time())
        # Enrollment/bootstrap metadata uses pair-aware retention (default 30d).
        # Do not independently delete enrollment files; that left orphan tickets.
        self.expire_nonces(now)
        self.cleanup_expired_bootstrap_tickets(now, force=True)

    def load_nonces(self):
        path = self.nonce_file
        if not path.exists():
            return {'schema_version': 1, 'nonces': {}}
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistrySchemaError('unable to read an existing management nonce store') from exc
        if not isinstance(data, dict):
            raise RegistrySchemaError('unable to read an existing management nonce store')
        nonces = data.get('nonces')
        if not isinstance(nonces, dict):
            raise RegistrySchemaError('unable to read an existing management nonce store')
        return {'schema_version': 1, 'nonces': nonces}

    def save_nonces(self, data):
        atomic_write_json(self.nonce_file, data)

    def expire_nonces(self, now=None):
        now = int(now if now is not None else time.time())
        data = self.load_nonces()
        nonces = data['nonces']
        changed = False
        for key, exp in list(nonces.items()):
            try:
                expiry = int(exp)
            except (TypeError, ValueError):
                nonces.pop(key, None)
                changed = True
                continue
            if expiry < now:
                nonces.pop(key, None)
                changed = True
        if changed:
            self.save_nonces(data)
        return data

    def check_nonce(self, machine_id, nonce, now):
        """Return an error string if the nonce is unusable. Do not persist yet.

        Persistence happens in commit_nonce() after a successful registry save
        so a failed mutation does not burn a valid signed request.
        """
        if not NONCE_RE.fullmatch(nonce or ''):
            return 'invalid nonce'
        data = self.expire_nonces(now)
        nonces = data['nonces']
        key = f'{machine_id}:{nonce}'
        if key in nonces:
            return 'replayed request'
        return None

    def commit_nonce(self, machine_id, nonce, now):
        """Persist a nonce after the matching mutation has been committed.

        Never evict a nonce that is still inside the replay-protection horizon
        (MAX_CLOCK_SKEW). When the per-client cap is exhausted by still-valid
        entries, reject new signed requests with a bounded-resource error
        instead of re-enabling replay of an earlier request.
        """
        if not NONCE_RE.fullmatch(nonce or ''):
            return 'invalid nonce'
        data = self.expire_nonces(now)
        nonces = data['nonces']
        key = f'{machine_id}:{nonce}'
        if key in nonces:
            return 'replayed request'
        prefix = machine_id + ':'
        # Expiry timestamps are absolute; an entry remains replay-blocking while
        # now < exp. A signed request accepted with future skew can remain
        # cryptographically valid for up to 2*MAX_CLOCK_SKEW after commit, so
        # never drop entries younger than that under size pressure.
        protect_after_commit = 2 * MAX_CLOCK_SKEW
        horizon_floor = now + (MGMT_NONCE_TTL - protect_after_commit)
        owned = sorted(
            ((k, nonces[k]) for k in list(nonces) if k.startswith(prefix)),
            key=lambda item: item[1],
        )
        while len(owned) >= MAX_NONCES_PER_CLIENT:
            old_key, old_exp = owned[0]
            # Still inside the signature acceptance window → refuse eviction.
            if old_exp > horizon_floor:
                return 'nonce store full; retry later'
            owned.pop(0)
            nonces.pop(old_key, None)
        nonces[key] = now + MGMT_NONCE_TTL
        self.save_nonces(data)
        return None

    def consume_nonce(self, machine_id, nonce, now):
        """Replay defense: a captured signed request cannot be reused.

        Nonces are stored as machine_id:nonce -> expiry. Entries expire after
        MGMT_NONCE_TTL seconds (900), which is longer than MAX_CLOCK_SKEW so a
        request stays non-replayable for its entire accepted timestamp window.
        Per-client count is capped; entries still inside the skew window are
        never evicted — capacity exhaustion returns a transient error instead.

        Callers that need check-then-commit around a registry mutation should
        use check_nonce() + commit_nonce() instead.
        """
        error = self.check_nonce(machine_id, nonce, now)
        if error:
            return error
        return self.commit_nonce(machine_id, nonce, now)

    @staticmethod
    def mgmt_status(client):
        if not isinstance(client, dict):
            return 'legacy'
        status = client.get('mgmt_status')
        if status in ('enrolled', 'legacy', 'revoked'):
            return status
        if client.get('mgmt_pubkey'):
            return 'enrolled'
        return 'legacy'

    def register_mgmt_identity(self, client, payload, enrollment_secret, machine_id):
        raw = payload.get('mgmt_pubkey')
        if raw in (None, ''):
            if not client.get('mgmt_status'):
                client['mgmt_status'] = self.mgmt_status(client)
            return None, None
        try:
            pem = MGMT.canonicalize_pubkey_pem(raw)
            fingerprint = MGMT.pubkey_fingerprint(pem)
        except Exception:
            return None, 'invalid management public key'
        alg = str(payload.get('mgmt_alg') or MGMT.MGMT_ALG).strip().lower()
        if alg != MGMT.MGMT_ALG:
            return None, 'unsupported management signature algorithm'
        mac = MGMT.derive_mac_key(enrollment_secret, machine_id)
        now_iso = utc_now_iso()
        existing_pem = client.get('mgmt_pubkey')
        status = self.mgmt_status(client)
        same = False
        if status == 'enrolled' and existing_pem:
            try:
                same = MGMT.canonicalize_pubkey_pem(existing_pem) == pem
            except Exception:
                same = False
        client['mgmt_pubkey'] = pem
        client['mgmt_alg'] = MGMT.MGMT_ALG
        client['mgmt_fingerprint'] = fingerprint
        client['mgmt_status'] = 'enrolled'
        client['mgmt_mac_key'] = mac
        if not same:
            client['mgmt_enrolled_at'] = now_iso
        client['mgmt_revoked_at'] = None
        return mac, None

    def verify_mgmt_against_client(self, client, machine_id, headers, body, op=None, method=None, path=None):
        try:
            ts = int(str(headers.get('X-Timestamp') or headers.get('X-Mgmt-Timestamp') or ''))
        except Exception:
            return 'invalid timestamp', None, None
        nonce = str(headers.get('X-Mgmt-Nonce') or '').strip().lower()
        signature = str(headers.get('X-Mgmt-Signature') or '').strip()
        if not signature:
            return 'missing signature', None, None
        now = int(time.time())
        if abs(now - ts) > MAX_CLOCK_SKEW:
            return 'request timestamp outside allowed window', None, None
        if not isinstance(client, dict):
            return 'unknown client identity', None, None
        status = self.mgmt_status(client)
        if status == 'revoked':
            return (
                "this client's management identity has been revoked. "
                'Run the server enrollment command to create a new Enrollment Code, '
                'then re-enroll this client.'
            ), None, None
        if status != 'enrolled' or not client.get('mgmt_pubkey'):
            return 'this client does not have a management identity', None, None
        sign_op = op if op is not None else MGMT.MGMT_OP_ENROLL
        message = MGMT.signed_message(
            machine_id, body, ts, nonce, op=sign_op, method=method, path=path
        )
        try:
            ok = MGMT.verify_signature(client['mgmt_pubkey'], message, signature)
        except ValueError as exc:
            return str(exc), None, None
        if not ok:
            return 'invalid signature', None, None
        nonce_error = self.check_nonce(machine_id, nonce, now)
        if nonce_error:
            return nonce_error, None, None
        return None, now, nonce

    def verify_request(self, enrollment_id, timestamp, signature, body):
        record, path = self.load_enrollment(enrollment_id)
        if not record:
            return None, None, 'unknown enrollment id'

        now = int(time.time())
        try:
            ts = int(timestamp)
        except Exception:
            return None, None, 'invalid timestamp'

        if abs(now - ts) > MAX_CLOCK_SKEW:
            return None, None, 'request timestamp outside allowed window'
        if record.get('revoked_at'):
            return None, None, 'enrollment code revoked'
        if now > int(record.get('expires_at', 0)):
            return None, None, 'enrollment code expired'

        secret = record.get('secret', '')
        expected = hmac_hex(secret, timestamp + '\n' + body.decode())
        if not hmac.compare_digest(expected, signature or ''):
            return None, None, 'invalid signature'
        # used_at is intentionally NOT rejected here: enroll() distinguishes
        # exact lost-response idempotent retry from authority-changing reuse.
        return record, path, None

    def _used_enrollment_idempotent_replay(self, client, payload, requested):
        """Allow exact lost-response retry of an already-consumed Enrollment Code.

        Requires same machine (caller), same management public key, and the same
        enabled service set. Rejects any authority / identity change.
        Returns (allocated_list, error_message).
        """
        if not isinstance(client, dict):
            return None, 'enrollment code already used'
        raw = payload.get('mgmt_pubkey')
        stored_pem = client.get('mgmt_pubkey')
        if raw not in (None, ''):
            try:
                presented = MGMT.canonicalize_pubkey_pem(raw)
            except Exception:
                return None, 'invalid management public key'
            if not stored_pem:
                return None, 'enrollment code already used'
            try:
                stored = MGMT.canonicalize_pubkey_pem(stored_pem)
            except Exception:
                return None, 'enrollment code already used'
            if presented != stored:
                return None, 'enrollment code already used'
        elif stored_pem:
            # Prior enrollment established an identity; retry must present it.
            return None, 'enrollment code already used'

        existing = client.get('services') or {}
        if not isinstance(existing, dict):
            return None, 'enrollment code already used'
        enabled_ids = {
            sid for sid, rec in existing.items()
            if isinstance(rec, dict) and rec.get('enabled')
        }
        requested_ids = {spec['id'] for spec in requested}
        if enabled_ids != requested_ids:
            return None, 'enrollment code already used'
        allocated = []
        for spec in requested:
            prev = existing.get(spec['id']) or {}
            if not isinstance(prev, dict) or not prev.get('enabled'):
                return None, 'enrollment code already used'
            try:
                prev_port = int(prev.get('local_port'))
                want_port = int(spec['local_port'])
            except (TypeError, ValueError):
                return None, 'enrollment code already used'
            if (
                str(prev.get('local_ip') or '') != str(spec.get('local_ip') or '')
                or prev_port != want_port
                or str(prev.get('preset') or '') != str(spec.get('preset') or '')
            ):
                return None, 'enrollment code already used'
            remote_port = coerce_port(prev.get('remote_port'))
            if remote_port is None:
                return None, 'enrollment code already used'
            allocated.append({'id': spec['id'], 'remote_port': remote_port})
        return allocated, None

    def reconcile_client_registry(self, machine_id, headers, body, peer_host=None):
        registry_service_ids = []
        response_mac_key = None
        pending_nonce = None
        try:
            with LOCK:
                with self.registry_lock():
                    state = self.load_registry()
                    client = (state.get('clients') or {}).get(machine_id)
                    error, _now, pending_nonce = self.verify_mgmt_against_client(
                        client, machine_id, headers, body
                    )
                    if error:
                        return 403, api_error(error, classify_auth_error(error))
                    if not isinstance(client, dict):
                        return 403, api_error('unknown client identity', 'AUTH_FAILED')

                    services = client.get('services') or {}
                    if not isinstance(services, dict):
                        services = {}
                    registry_service_ids = sorted(str(sid) for sid in services.keys())

                    if pending_nonce:
                        nonce_error = self.commit_nonce(
                            machine_id, pending_nonce, int(time.time())
                        )
                        if nonce_error:
                            return 403, api_error(
                                nonce_error, classify_auth_error(nonce_error)
                            )

                    response_mac_key = client.get('mgmt_mac_key')
        except RegistrySchemaError as exc:
            print('allocator registry error: %s' % exc, flush=True)
            return 500, api_error(
                'registry schema is invalid', 'REGISTRY_INVALID'
            )
        except OSError as exc:
            print('allocator persist error: %s' % exc, flush=True)
            return 500, api_error(
                'failed to persist registry', 'SERVER_MUTATION_FAILED'
            )
        except RuntimeError as exc:
            print('allocator runtime error: %s' % exc, flush=True)
            return 500, api_error(
                'internal server error', 'SERVER_MUTATION_FAILED'
            )

        if not response_mac_key:
            return 500, api_error(
                'management response authentication is not available',
                'SERVER_MUTATION_FAILED',
            )

        response_payload = {
            'frp_server': cfg_public_host(self.cfg),
            'frp_server_port': cfg_frp_control_public_port(self.cfg),
            'frp_transport': cfg_frp_transport(self.cfg),
            'registry_service_ids': registry_service_ids,
        }
        response_payload['public_hostname'] = cfg_public_hostname(self.cfg)
        response_payload['response_hmac'] = MGMT.hmac_hex(
            response_mac_key, canonical_json(response_payload)
        )
        return 200, response_payload

    def enroll(self, enrollment_id, timestamp, signature, body, headers=None, peer_host=None):
        headers = headers or {}
        identity_auth = str(headers.get('X-Mgmt-Auth') or '').strip() == '1'
        source_ip = CREG.request_source_ip(peer_host, headers)

        record = None
        enroll_path = None
        if not identity_auth:
            record, enroll_path, error = self.verify_request(
                enrollment_id, timestamp, signature, body
            )
            if error:
                return 403, api_error(error, classify_auth_error(error))

        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError:
            return 400, api_error('invalid JSON', 'AUTH_FAILED')
        if not isinstance(payload, dict):
            return 400, api_error('invalid JSON', 'AUTH_FAILED')

        machine_id = str(payload.get('machine_id', '')).strip()
        hostname = str(payload.get('hostname', '')).strip()
        if MID is not None:
            try:
                machine_id = MID.validate_machine_id(machine_id, required=True)
            except MID.MachineIdError as exc:
                return 400, api_error(str(exc), 'AUTH_FAILED')
        else:
            if not machine_id:
                return 400, api_error('machine_id is required', 'AUTH_FAILED')
            if len(machine_id) > MACHINE_ID_MAX_LEN or any(c in machine_id for c in '\r\n/\\'):
                return 400, api_error('invalid machine_id', 'AUTH_FAILED')
            if any(ord(c) < 0x20 or (0x7F <= ord(c) <= 0x9F) for c in machine_id):
                return 400, api_error('invalid machine_id', 'AUTH_FAILED')
        try:
            hostname = CREG.validate_hostname(hostname)
        except ValueError:
            return 400, api_error('invalid hostname', 'AUTH_FAILED')

        if identity_auth and str(headers.get('X-Mgmt-Reconcile') or '').strip() == '1':
            return self.reconcile_client_registry(machine_id, headers, body, peer_host)

        try:
            requested = normalize_services(payload.get('services'))
        except ServiceValidationError as exc:
            cls = 'SERVICE_ALREADY_EXISTS' if 'duplicate' in str(exc).lower() else 'AUTH_FAILED'
            return 400, api_error(str(exc), cls)

        issued_mac = None
        pending_nonce = None
        allocated = []
        response_mac_key = None

        try:
            with LOCK:
                with self.registry_lock():
                    if not identity_auth:
                        record, enroll_path = self.load_enrollment(enrollment_id)
                        if not record:
                            return 403, api_error('unknown enrollment id', 'AUTH_FAILED')
                        bound_machine_id = record.get('bound_machine_id')
                        if bound_machine_id and bound_machine_id != machine_id:
                            return 403, api_error(
                                'enrollment code is already bound to another machine',
                                'AUTH_FAILED',
                            )
                        # Bootstrap-ticket enrollments carry an authorized
                        # service scope. The Enrollment Code proves possession,
                        # not authority to widen that scope (an empty list is a
                        # management-only ticket and is enforced as such).
                        # Manual enrollment records have no scope and keep the
                        # client-supplied service set.
                        if 'authorized_services' in record:
                            if not services_match_authorized(
                                requested, record.get('authorized_services')
                            ):
                                return 403, api_error(
                                    'enrollment services do not match authorized '
                                    'ticket scope',
                                    'SERVICE_SCOPE_VIOLATION',
                                )

                    state = self.load_registry()
                    clients = state.setdefault('clients', {})
                    client = clients.get(machine_id)

                    if not identity_auth and record is not None and record.get('used_at'):
                        # Consumed Enrollment Codes are not fresh credentials.
                        # Exact lost-response retry (same machine, same mgmt key,
                        # same services) may recover the committed response.
                        # Any authority change requires a new Enrollment Code.
                        if not bound_machine_id:
                            return 403, api_error(
                                'enrollment code already used', 'AUTH_FAILED'
                            )
                        allocated, replay_error = self._used_enrollment_idempotent_replay(
                            client, payload, requested
                        )
                        if replay_error:
                            return 403, api_error(replay_error, 'AUTH_FAILED')
                    elif identity_auth:
                        now_iso = utc_now_iso()
                        error, _now, pending_nonce = self.verify_mgmt_against_client(
                            client, machine_id, headers, body
                        )
                        if error:
                            return 403, api_error(error, classify_auth_error(error))
                        if payload.get('mgmt_pubkey'):
                            try:
                                presented = MGMT.canonicalize_pubkey_pem(payload.get('mgmt_pubkey'))
                                stored = MGMT.canonicalize_pubkey_pem(client.get('mgmt_pubkey'))
                            except Exception:
                                return 403, api_error(
                                    'invalid management public key', 'AUTH_FAILED'
                                )
                            if presented != stored:
                                return 403, api_error(
                                    'management public key does not match this client',
                                    'AUTH_FAILED',
                                )
                        if client is None:
                            return 403, api_error('unknown client identity', 'AUTH_FAILED')
                        previous_client = json.loads(json.dumps(client))
                        client['hostname'] = hostname or client.get('hostname', '')
                        client['last_enrolled_at'] = now_iso
                        if not isinstance(client.get('services'), dict):
                            client['services'] = {}
                        CREG.apply_observed_fields(
                            client,
                            hostname=hostname,
                            source_ip=source_ip,
                            seen_at=now_iso,
                        )
                        CREG.seed_admin_metadata(
                            client,
                            label=(record or {}).get('label'),
                            note=(record or {}).get('note'),
                        )
                        existing_services = dict(client.get('services') or {})
                        used = self.used_ports(state)
                        updated = {}
                        requested_ids = {svc['id'] for svc in requested}

                        for sid, rec in existing_services.items():
                            if sid in requested_ids:
                                continue
                            kept = dict(rec)
                            kept['enabled'] = False
                            updated[sid] = kept

                        allocated = []
                        for spec in requested:
                            sid = spec['id']
                            previous = existing_services.get(sid) or {}
                            remote_port = coerce_port(previous.get('remote_port'))
                            if remote_port is None:
                                remote_port = self.allocate_port(used)
                                used.add(remote_port)
                            stored = {
                                'name': spec['name'],
                                'protocol': 'tcp',
                                'local_ip': spec['local_ip'],
                                'local_port': spec['local_port'],
                                'remote_port': remote_port,
                                'preset': spec['preset'],
                                'enabled': True,
                            }
                            if spec.get('preset') == 'ssh' and spec.get('ssh_user'):
                                stored['ssh_user'] = spec['ssh_user']
                            if 'health_check' in spec:
                                stored['health_check'] = spec['health_check']
                            updated[sid] = stored
                            allocated.append({
                                'id': sid,
                                'remote_port': remote_port,
                            })

                        client['services'] = updated
                        self.save_registry(state)
                        sync_enrollment_to_control_plane(self.cfg, client, machine_id)

                        if pending_nonce:
                            try:
                                nonce_error = self.commit_nonce(
                                    machine_id, pending_nonce, int(time.time())
                                )
                            except OSError as exc:
                                # Registry mutation must not stick when nonce
                                # persistence fails: otherwise the caller sees
                                # failure while the signed request remains
                                # replayable against the new authority state.
                                clients[machine_id] = previous_client
                                self.save_registry(state)
                                print(
                                    'allocator nonce persist error after mutation: %s'
                                    % exc,
                                    flush=True,
                                )
                                return 500, api_error(
                                    'failed to persist management nonce',
                                    'SERVER_MUTATION_FAILED',
                                )
                            if nonce_error:
                                clients[machine_id] = previous_client
                                self.save_registry(state)
                                return 403, api_error(
                                    nonce_error, classify_auth_error(nonce_error)
                                )
                        response_mac_key = client.get('mgmt_mac_key')
                    else:
                        previous_client = (
                            json.loads(json.dumps(client))
                            if isinstance(client, dict)
                            else None
                        )
                        previous_enrollment = (
                            json.loads(json.dumps(record))
                            if isinstance(record, dict)
                            else None
                        )
                        now_iso = utc_now_iso()

                        if client is None:
                            client = {
                                'hostname': hostname,
                                'created_at': now_iso,
                                'last_enrolled_at': now_iso,
                                'mgmt_status': 'legacy',
                                'services': {},
                            }
                            CREG.seed_admin_metadata(
                                client,
                                label=(record or {}).get('label'),
                                note=(record or {}).get('note'),
                            )
                            clients[machine_id] = client
                        else:
                            client['hostname'] = hostname or client.get('hostname', '')
                            client['last_enrolled_at'] = now_iso
                            if not isinstance(client.get('services'), dict):
                                client['services'] = {}
                            CREG.seed_admin_metadata(
                                client,
                                label=(record or {}).get('label'),
                                note=(record or {}).get('note'),
                            )

                        if client is None:
                            return 403, api_error('unknown client identity', 'AUTH_FAILED')
                        client['hostname'] = hostname or client.get('hostname', '')
                        client['last_enrolled_at'] = now_iso
                        if not isinstance(client.get('services'), dict):
                            client['services'] = {}
                        CREG.apply_observed_fields(
                            client,
                            hostname=hostname,
                            source_ip=source_ip,
                            seen_at=now_iso,
                        )
                        CREG.seed_admin_metadata(
                            client,
                            label=(record or {}).get('label'),
                            note=(record or {}).get('note'),
                        )

                        issued_mac, ident_error = self.register_mgmt_identity(
                            client, payload, record['secret'], machine_id
                        )
                        if ident_error:
                            return 400, api_error(ident_error, 'AUTH_FAILED')

                        existing_services = dict(client.get('services') or {})
                        used = self.used_ports(state)
                        updated = {}
                        requested_ids = {svc['id'] for svc in requested}

                        for sid, rec in existing_services.items():
                            if sid in requested_ids:
                                continue
                            kept = dict(rec)
                            kept['enabled'] = False
                            updated[sid] = kept

                        allocated = []
                        for spec in requested:
                            sid = spec['id']
                            previous = existing_services.get(sid) or {}
                            remote_port = coerce_port(previous.get('remote_port'))
                            if remote_port is None:
                                remote_port = self.allocate_port(used)
                                used.add(remote_port)
                            stored = {
                                'name': spec['name'],
                                'protocol': 'tcp',
                                'local_ip': spec['local_ip'],
                                'local_port': spec['local_port'],
                                'remote_port': remote_port,
                                'preset': spec['preset'],
                                'enabled': True,
                            }
                            if spec.get('preset') == 'ssh' and spec.get('ssh_user'):
                                stored['ssh_user'] = spec['ssh_user']
                            if 'health_check' in spec:
                                stored['health_check'] = spec['health_check']
                            updated[sid] = stored
                            allocated.append({
                                'id': sid,
                                'remote_port': remote_port,
                            })

                        client['services'] = updated
                        self.save_registry(state)
                        sync_enrollment_to_control_plane(self.cfg, client, machine_id)

                        def _rollback_enrollment_attempt():
                            if previous_client is None:
                                clients.pop(machine_id, None)
                            else:
                                clients[machine_id] = previous_client
                            self.save_registry(state)
                            if (
                                previous_enrollment is not None
                                and enroll_path is not None
                            ):
                                self.save_enrollment(enroll_path, previous_enrollment)

                        try:
                            _test_enrollment_failure_point('AFTER_REGISTRY_COMMIT')
                        except Exception:
                            _rollback_enrollment_attempt()
                            raise

                        if record is not None and enroll_path is not None:
                            record['bound_machine_id'] = machine_id
                            record['used_at'] = record.get('used_at') or now_iso
                            record['last_used_at'] = now_iso
                            try:
                                self.save_enrollment(enroll_path, record)
                            except Exception:
                                # Fail closed: never leave registry enrolled while
                                # the enrollment record remains unused/unbound.
                                _rollback_enrollment_attempt()
                                raise
                            try:
                                _test_enrollment_failure_point(
                                    'AFTER_ENROLLMENT_RECORD_COMMIT'
                                )
                            except Exception:
                                # Enrollment record already committed with registry.
                                # Leave recoverable committed generation; do not
                                # resurrect an unused enrollment code.
                                raise
                            completed = self.complete_bootstrap_for_enrollment(
                                record.get('id') or enrollment_id, machine_id
                            )
                            if not completed:
                                # Fail closed: never report enrollment success while the
                                # bootstrap ticket remains reusable. Roll back registry
                                # and enrollment mutations from this attempt.
                                _rollback_enrollment_attempt()
                                raise OSError(
                                    'failed to consume bootstrap ticket after enrollment'
                                )
                            try:
                                _test_enrollment_failure_point('AFTER_BOOTSTRAP_CONSUME')
                            except Exception:
                                # Bootstrap already consumed; leave recoverable committed
                                # generation (registry + enrollment bound). Do not resurrect
                                # an unused enrollment code after bootstrap was spent.
                                raise
                        response_mac_key = None
        except RegistrySchemaError as exc:
            print('allocator registry error: %s' % exc, flush=True)
            return 500, api_error(
                'registry schema is invalid', 'REGISTRY_INVALID'
            )
        except PortRangeExhausted as exc:
            print('allocator port range exhausted: %s' % exc, flush=True)
            return 500, api_error(
                'no free ports remain in the configured range',
                'PORT_RANGE_EXHAUSTED',
            )
        except OSError as exc:
            print('allocator persist error: %s' % exc, flush=True)
            return 500, api_error(
                'failed to persist registry', 'SERVER_MUTATION_FAILED'
            )
        except RuntimeError as exc:
            print('allocator runtime error: %s' % exc, flush=True)
            return 500, api_error(
                'internal server error', 'SERVER_MUTATION_FAILED'
            )

        response_payload = {
            'frp_server': cfg_public_host(self.cfg),
            'frp_server_port': cfg_frp_control_public_port(self.cfg),
            'frp_transport': cfg_frp_transport(self.cfg),
            'services': allocated,
        }
        response_payload['public_hostname'] = cfg_public_hostname(self.cfg)
        if identity_auth:
            mac_secret = response_mac_key
            if not mac_secret:
                return 500, api_error(
                    'management response authentication is not available',
                    'SERVER_MUTATION_FAILED',
                )
            response_payload['response_hmac'] = MGMT.hmac_hex(
                mac_secret, canonical_json(response_payload)
            )
            return 200, response_payload

        secret = record['secret']
        token_ciphertext = encrypt_token(read_text(self.token_file), secret)
        response_payload['token_ciphertext'] = token_ciphertext
        if issued_mac:
            response_payload['mgmt_status'] = 'enrolled'
        response_payload['response_hmac'] = hmac_hex(secret, canonical_json(response_payload))
        return 200, response_payload




    def authenticate_mgmt_read(self, headers, body=b''):
        """Authenticate a management identity for read-only allocator GETs."""
        machine_id = str(
            headers.get('X-Machine-Id')
            or headers.get('X-Machine-ID')
            or headers.get('X-Client-Id')
            or ''
        ).strip()
        if MID is not None:
            try:
                machine_id = MID.validate_machine_id(machine_id, required=True)
            except MID.MachineIdError as exc:
                return None, str(exc)
        elif not machine_id:
            return None, 'missing machine id'
        with self.registry_lock():
            state = self.load_registry()
            client = (state.get('clients') or {}).get(machine_id)
            error, now, nonce = self.verify_mgmt_against_client(
                client, machine_id, headers, body
            )
            if error:
                return None, error
            if nonce:
                nonce_error = self.commit_nonce(machine_id, nonce, int(time.time()))
                if nonce_error:
                    return None, nonce_error
            return machine_id, None

    def list_profiles_payload(self):
        # Service Profiles JSON store retired; Published Services / presets are canonical.
        return []

    def get_profile_payload(self, selector):
        raise KeyError('service profiles retired; use published-service / service-preset')



def make_handler(allocator):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'drlink/1.2'
        timeout = ALLOCATOR_REQUEST_TIMEOUT_SEC
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            try:
                self.request.settimeout(ALLOCATOR_REQUEST_TIMEOUT_SEC)
            except OSError:
                pass

        def log_message(self, fmt, *args):
            try:
                message = fmt % args
            except Exception:
                message = str(fmt)
            message = redact_allocator_log_path(message)
            print('%s - %s' % (self.address_string(), message), flush=True)

        def send_json(self, code, data):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_bootstrap_headers(self, code, content_type, body):
            if isinstance(body, str):
                body = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Pragma', 'no-cache')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            self.wfile.write(body)

        def _request_path(self):
            parsed = urlparse(self.path)
            return parsed.path or '/'

        def _short_url_platform(self):
            parsed = urlparse(self.path)
            requested = (
                parse_qs(parsed.query, keep_blank_values=True)
                .get('platform', [''])[0]
                .strip()
                .lower()
            )
            if requested == 'windows':
                return 'windows'
            if requested == 'linux':
                return 'linux'
            user_agent = str(self.headers.get('User-Agent') or '')
            if 'powershell' in user_agent.lower():
                return 'windows'
            return 'linux'

        def _handle_short_url_get(self, path):
            match = SHORT_URL_PATH_RE.match(path)
            if not match:
                return False
            raw_ticket = match.group(1)
            # Safe uniform failure for invalid/expired/revoked/completed tickets.
            unavailable = 'bootstrap unavailable\n'
            if not allocator.short_url_bootstrap_available(raw_ticket):
                self._send_bootstrap_headers(
                    404, 'text/plain; charset=utf-8', unavailable
                )
                return True
            platform = self._short_url_platform()
            script = allocator.build_short_url_script(raw_ticket, platform)
            if not script:
                self._send_bootstrap_headers(
                    503, 'text/plain; charset=utf-8', unavailable
                )
                return True
            content_type = (
                'text/plain; charset=utf-8'
                if platform == 'windows'
                else 'text/x-shellscript; charset=utf-8'
            )
            self._send_bootstrap_headers(200, content_type, script)
            return True

        def _handle_artifact_get(self, path):
            if not path.startswith('/artifacts'):
                return False
            if QA is None:
                body = b'Required qualified artifact is not available on this DRLink Server.\n'
                self._send_bootstrap_headers(503, 'text/plain; charset=utf-8', body.decode('utf-8'))
                return True
            root = QA.installed_root()
            try:
                file_path = QA.resolve_http_path(root, path)
            except QA.ArtifactError:
                msg = QA.missing_artifact_error()
                self._send_bootstrap_headers(404, 'text/plain; charset=utf-8', msg)
                return True
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', QA.content_type_for(file_path))
            self.send_header('Content-Length', str(len(data)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)
            return True

        def _with_slot(self, fn):
            # Connection-level bounding is enforced by BoundedThreadingMixIn
            # before the worker thread starts. A second semaphore here deadlocks.
            if BOUNDED is None:
                acquired = _REQUEST_SLOTS.acquire(blocking=False)
                if not acquired:
                    self.send_json(
                        503,
                        api_error('server is busy; retry later', 'SERVER_BUSY'),
                    )
                    return
                try:
                    return fn()
                finally:
                    _REQUEST_SLOTS.release()
            return fn()

        def do_GET(self):
            def _handle():
                allocator.reload_cfg_if_changed()
                path = self._request_path()
                if self._handle_short_url_get(path):
                    return
                if self._handle_artifact_get(path):
                    return
                if path == '/healthz':
                    try:
                        allocator.load_registry()
                    except RegistrySchemaError as exc:
                        self.send_json(
                            503,
                            {
                                'status': 'unhealthy',
                                'error': str(exc),
                            },
                        )
                        return
                    payload = {'status': 'ok'}
                    project_version = read_project_version(
                        os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
                    )
                    if project_version:
                        payload['project_version'] = project_version
                    # Supported upgrade order: server first, then clients.
                    # Clients may refuse updates when server is older.
                    payload['min_client_version'] = '2.1.1'
                    self.send_json(200, payload)
                    return
                if path == '/ca.crt':
                    ca_path = allocator.cfg.get('tls_ca_cert')
                    if not ca_path or not Path(ca_path).is_file():
                        self.send_json(
                            500, {'error': 'CA certificate is not available'}
                        )
                        return
                    body = Path(ca_path).read_bytes()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-pem-file')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == '/v1/profiles' or path.startswith('/v1/profiles/'):
                    if PROF is None:
                        self.send_json(
                            503,
                            api_error(
                                'service profiles are unavailable on this server',
                                'SERVER_MUTATION_FAILED',
                            ),
                        )
                        return
                    _mid, auth_error = allocator.authenticate_mgmt_read(self.headers, b'')
                    if auth_error:
                        self.send_json(
                            403, api_error(auth_error, classify_auth_error(auth_error))
                        )
                        return
                    try:
                        if path == '/v1/profiles':
                            self.send_json(
                                200, {'profiles': allocator.list_profiles_payload()}
                            )
                            return
                        selector = path[len('/v1/profiles/'):]
                        if not selector or '/' in selector:
                            self.send_json(404, {'error': 'not found'})
                            return
                        from urllib.parse import unquote
                        selector = unquote(selector)
                        self.send_json(200, allocator.get_profile_payload(selector))
                        return
                    except Exception as exc:
                        # ProfileError / KeyError -> 404
                        msg = str(exc) or 'profile not found'
                        lowered = msg.lower()
                        if 'unknown profile' in lowered or 'unavailable' in lowered:
                            self.send_json(404, api_error(msg, 'AUTH_FAILED'))
                            return
                        print('allocator profile error: %s' % exc, flush=True)
                        self.send_json(
                            500,
                            api_error('internal server error', 'SERVER_MUTATION_FAILED'),
                        )
                        return
                if path == '/v1/catalog' and MGMT_SYNC is not None:
                    plane = _open_control_plane(allocator.cfg)
                    if plane is None:
                        self.send_json(
                            503,
                            api_error(
                                'control plane unavailable',
                                'SERVER_MUTATION_FAILED',
                            ),
                        )
                        return
                    try:
                        handled = MGMT_SYNC.handle_allocator_http(
                            plane,
                            'GET',
                            path,
                            self.headers,
                            b'',
                            verifier=MGMT_SYNC.AllocatorMgmtVerifier(allocator),
                        )
                        if handled is not None:
                            self.send_json(handled[0], handled[1])
                            return
                    finally:
                        try:
                            plane.close()
                        except Exception:
                            pass
                self.send_json(404, {'error': 'not found'})

            self._with_slot(_handle)

        def do_POST(self):
            def _handle():
                allocator.reload_cfg_if_changed()
                path = self._request_path()
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    # AI job completion may carry bounded file payloads (content_b64).
                    max_len = 1200 * 1024 if path == '/v1/ai-jobs/complete' else 65536
                    if length <= 0 or length > max_len:
                        self.send_json(
                            400, {'error': 'invalid request body length'}
                        )
                        return
                    body = self.rfile.read(length)
                except Exception:
                    self.send_json(
                        400, {'error': 'invalid request body length'}
                    )
                    return
                try:
                    if path == '/enroll':
                        peer_host = ''
                        try:
                            peer_host = self.client_address[0]
                        except Exception:
                            peer_host = ''
                        code, result = allocator.enroll(
                            self.headers.get('X-Enrollment-ID', ''),
                            self.headers.get('X-Timestamp', ''),
                            self.headers.get('X-Signature', ''),
                            body,
                            headers=self.headers,
                            peer_host=peer_host,
                        )
                        self.send_json(code, result)
                        return
                    if path == '/bootstrap/redeem':
                        code, result = allocator.redeem_bootstrap(body)
                        self.send_json(code, result)
                        return
                    if path in (
                        '/v1/remote-services',
                        '/v1/remote-services-status',
                        '/v1/ai-jobs/claim',
                        '/v1/ai-jobs/complete',
                    ) and MGMT_SYNC is not None:
                        plane = _open_control_plane(allocator.cfg)
                        if plane is None:
                            self.send_json(
                                503,
                                api_error(
                                    'control plane unavailable',
                                    'SERVER_MUTATION_FAILED',
                                ),
                            )
                            return
                        try:
                            handled = MGMT_SYNC.handle_allocator_http(
                                plane,
                                'POST',
                                path,
                                self.headers,
                                body,
                                verifier=MGMT_SYNC.AllocatorMgmtVerifier(allocator),
                            )
                            if handled is not None:
                                self.send_json(handled[0], handled[1])
                                return
                        finally:
                            try:
                                plane.close()
                            except Exception:
                                pass
                    self.send_json(404, {'error': 'not found'})
                except json.JSONDecodeError:
                    self.send_json(400, api_error('invalid JSON', 'AUTH_FAILED'))
                except RegistrySchemaError as exc:
                    print('allocator registry error: %s' % exc, flush=True)
                    self.send_json(
                        500,
                        api_error(
                            'registry schema is invalid', 'REGISTRY_INVALID'
                        ),
                    )
                except PortRangeExhausted as exc:
                    print(
                        'allocator port range exhausted: %s' % exc, flush=True
                    )
                    self.send_json(
                        500,
                        api_error(
                            'no free ports remain in the configured range',
                            'PORT_RANGE_EXHAUSTED',
                        ),
                    )
                except Exception as exc:
                    print('allocator request error: %s' % exc, flush=True)
                    self.send_json(
                        500,
                        api_error(
                            'internal server error', 'SERVER_MUTATION_FAILED'
                        ),
                    )

            self._with_slot(_handle)

        def do_DELETE(self):
            def _handle():
                allocator.reload_cfg_if_changed()
                path = self._request_path()
                if path.startswith('/v1/remote-services/') and MGMT_SYNC is not None:
                    plane = _open_control_plane(allocator.cfg)
                    if plane is None:
                        self.send_json(
                            503,
                            api_error(
                                'control plane unavailable',
                                'SERVER_MUTATION_FAILED',
                            ),
                        )
                        return
                    try:
                        handled = MGMT_SYNC.handle_allocator_http(
                            plane,
                            'DELETE',
                            path,
                            self.headers,
                            b'',
                            verifier=MGMT_SYNC.AllocatorMgmtVerifier(allocator),
                        )
                        if handled is not None:
                            self.send_json(handled[0], handled[1])
                            return
                    finally:
                        try:
                            plane.close()
                        except Exception:
                            pass
                self.send_json(404, {'error': 'not found'})

            self._with_slot(_handle)

    return Handler


def allocator_ssl_context(cfg):
    cert = str(cfg.get('tls_server_cert') or '').strip()
    key = str(cfg.get('tls_server_key') or '').strip()
    if not cert or not key:
        raise SystemExit(
            'ERROR: allocator TLS certificate or key is missing; refusing to start plain HTTP'
        )
    if not Path(cert).is_file() or not Path(key).is_file():
        raise SystemExit(
            'ERROR: allocator TLS certificate or key is missing; refusing to start plain HTTP'
        )
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    except AttributeError:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    if hasattr(ssl, 'TLSVersion'):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= getattr(ssl, 'OP_NO_SSLv2', 0)
        context.options |= getattr(ssl, 'OP_NO_SSLv3', 0)
        context.options |= getattr(ssl, 'OP_NO_TLSv1', 0)
        context.options |= getattr(ssl, 'OP_NO_TLSv1_1', 0)
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except Exception as exc:
        raise SystemExit('ERROR: allocator TLS configuration is invalid: %s' % exc) from exc
    return context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()

    allocator = Allocator(args.config)
    try:
        allocator.load_registry()
    except RegistrySchemaError as exc:
        # Missing registry: stay up but unhealthy (/healthz=503, mutations fail).
        # Other schema/corruption errors remain fatal at boot.
        if not allocator.registry_present():
            print('ERROR: %s' % exc, flush=True)
        else:
            raise SystemExit(f'ERROR: {exc}') from exc
    try:
        import drlink_upgrade_reconcile as UR

        rec = UR.reconcile_from_allocator(allocator)
        if rec.get('ok') and rec.get('applied'):
            print(
                'upgrade reconcile applied clients=%s hosts=%s path=%s'
                % (
                    (rec.get('after') or rec.get('plan') or {}).get('sqlite_clients'),
                    (rec.get('after') or rec.get('plan') or {}).get('managed_hosts'),
                    rec.get('path') or '',
                ),
                flush=True,
            )
        elif rec.get('ok') and rec.get('skipped'):
            print('upgrade reconcile already converged', flush=True)
        elif not rec.get('ok'):
            print('WARNING: upgrade reconcile did not apply: %s' % rec.get('error'), flush=True)
    except Exception as exc:
        print('WARNING: upgrade reconcile failed (existing state preserved): %s' % exc, flush=True)
    allocator.cleanup_expired_enrollments()
    host = allocator.cfg.get('listen_host', '0.0.0.0')
    port = cfg_allocator_listen_port(allocator.cfg)
    if port is None:
        raise SystemExit('ERROR: allocator_listen_port is not configured')
    context = allocator_ssl_context(allocator.cfg)
    handler = make_handler(allocator)
    if BOUNDED is None:
        raise SystemExit(BOUNDED_LOAD_ERROR)

    def _reject(request, _addr):
        # Overload path receives a raw TCP socket (TLS is deferred to workers).
        # Close without attempting an HTTP reply — clients expect TLS.
        try:
            request.close()
        except OSError:
            pass

    class AllocatorServer(BOUNDED.BoundedThreadingMixIn, HTTPServer):
        max_concurrent = ALLOCATOR_MAX_CONCURRENT
        request_timeout = float(ALLOCATOR_REQUEST_TIMEOUT_SEC)
        handshake_timeout = float(ALLOCATOR_TLS_HANDSHAKE_TIMEOUT_SEC)
        daemon_threads = True
        reject_callback = staticmethod(_reject)
        ssl_context = context

        def prepare_request(self, request, client_address):
            """Wrap + handshake in the worker so accept() stays non-blocking."""
            del client_address
            ctx = self.ssl_context
            hs_timeout = float(self.handshake_timeout)
            try:
                request.settimeout(hs_timeout)
            except (OSError, AttributeError):
                pass
            ssl_sock = ctx.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
            try:
                ssl_sock.settimeout(hs_timeout)
                ssl_sock.do_handshake()
                ssl_sock.settimeout(float(self.request_timeout))
            except Exception:
                try:
                    ssl_sock.close()
                except OSError:
                    pass
                raise
            return ssl_sock

    # Plain listen → accept raw → worker does bounded TLS handshake.
    # Wrapping the listening socket would run handshake inside accept() and
    # starve healthy clients when peers stall mid-ClientHello (AUDIT-004).
    server = AllocatorServer((host, port), handler)
    print(f'FRP allocator listening on https://{host}:{port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
