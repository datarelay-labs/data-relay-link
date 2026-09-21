#!/usr/bin/env python3
"""Client management identity helpers (P2.3).

Algorithm choice
----------------
ECDSA P-256 with SHA-256 via OpenSSL (`openssl dgst -sha256 -sign/-verify`).

Ed25519 is a strong default where OpenSSL 1.1.1+ is guaranteed. This project
still supports Amazon Linux 2 (OpenSSL 1.0.2), where Ed25519 is unavailable.
ECDSA P-256 is a standard, non-custom primitive and the same OpenSSL CLI works
from OpenSSL 1.0.2 through 3.x, matching the existing OpenSSL dependency.

This module does not implement original cryptography. It shells out to OpenSSL.

Canonical signed object (mgmt schema 1)
---------------------------------------
The signed bytes are canonical JSON:

  json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

with UTF-8 encoding and these fields only:

  {
    "alg": "ecdsa-p256-sha256",
    "body_sha256": "<hex SHA-256 of the exact HTTP body bytes>",
    "machine_id": "<client machine identity>",
    "nonce": "<64 lowercase hex chars, 32 bytes>",
    "op": "enroll",
    "schema": 1,
    "ts": <unix seconds as JSON integer>
  }

The signature is ECDSA-SHA256 over those canonical bytes (OpenSSL DER), then
standard Base64 without newlines.

The signed object binds protocol version, algorithm, client/machine identity,
operation, timestamp, nonce, and payload digest. Optional method/path fields
bind later management API operations without changing enroll signatures.
Do not sign ad-hoc string concatenation.

Private keys stay on the client. The server stores the public key PEM, a
SHA-256 fingerprint of the DER public key, a response MAC key, and status.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MGMT_ALG = 'ecdsa-p256-sha256'
MGMT_SIGN_SCHEMA = 1
MGMT_OP_ENROLL = 'enroll'
MGMT_OP_CATALOG_READ = 'catalog.read'
MGMT_OP_REMOTE_SERVICE_SET = 'remote-service.set'
MGMT_OP_REMOTE_SERVICE_DELETE = 'remote-service.delete'
MGMT_OP_REMOTE_SERVICE_STATUS = 'remote-service.status'
MGMT_OP_AI_JOB_CLAIM = 'ai-job.claim'
MGMT_OP_AI_JOB_COMPLETE = 'ai-job.complete'
MGMT_NONCE_HEX_LEN = 64
MGMT_MAX_CLOCK_SKEW = 300
MGMT_NONCE_RE = re.compile(r'^[0-9a-f]{64}$')
HEADER_MACHINE_ID = 'X-Machine-Id'
HEADER_TIMESTAMP = 'X-Timestamp'
HEADER_NONCE = 'X-Mgmt-Nonce'
HEADER_SIGNATURE = 'X-Mgmt-Signature'
HEADER_MGMT_AUTH = 'X-Mgmt-Auth'
PUBKEY_PEM_RE = re.compile(
    r'-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n?\Z'
)
MAX_PUBKEY_PEM_LEN = 4096


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hmac_hex(secret, message):
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def new_nonce():
    return secrets.token_hex(MGMT_NONCE_HEX_LEN // 2)


def new_mac_key():
    return secrets.token_hex(32)


def derive_mac_key(secret, machine_id):
    """Derive the response-auth MAC key from an Enrollment Code secret.

    HMAC-SHA256(enrollment_secret, "frp-mgmt-mac-v1\\n" + machine_id)

    The FRP token is never used. The private key is never used. This key
    authenticates later management responses and is stored on both sides;
    it is not sent in subsequent requests.
    """
    return hmac_hex(secret, 'frp-mgmt-mac-v1\n' + str(machine_id))


def signed_object(machine_id, body, ts, nonce, op=MGMT_OP_ENROLL, method=None, path=None):
    if isinstance(body, str):
        body_bytes = body.encode('utf-8')
    else:
        body_bytes = body
    obj = {
        'alg': MGMT_ALG,
        'body_sha256': sha256_hex(body_bytes),
        'machine_id': str(machine_id),
        'nonce': str(nonce).strip().lower(),
        'op': op,
        'schema': MGMT_SIGN_SCHEMA,
        'ts': int(ts),
    }
    method_text = str(method or '').strip()
    path_text = str(path or '').strip()
    # Optional fields are omitted so existing enroll signatures stay valid.
    if method_text:
        obj['method'] = method_text.upper()
    if path_text:
        obj['path'] = path_text
    return obj


def signed_message(machine_id, body, ts, nonce, op=MGMT_OP_ENROLL, method=None, path=None):
    return canonical_json(
        signed_object(machine_id, body, ts, nonce, op=op, method=method, path=path)
    )


def header_get(headers, name):
    """Read an HTTP header from HTTPMessage or a plain dict (case-insensitive)."""
    if headers is None:
        return ''
    getter = getattr(headers, 'get', None)
    if callable(getter):
        value = getter(name)
        if value not in (None, ''):
            return value
    try:
        keys = list(headers.keys())
    except Exception:
        return ''
    target = str(name).lower()
    for key in keys:
        if str(key).lower() == target:
            value = headers[key]
            if value not in (None, ''):
                return value
    return ''


def extract_machine_id(headers):
    """Authoritative caller identity header. X-Drlink-Machine-Id is not accepted."""
    return str(
        header_get(headers, HEADER_MACHINE_ID)
        or header_get(headers, 'X-Machine-ID')
        or ''
    ).strip()


def parse_mgmt_timestamp(headers):
    raw = str(
        header_get(headers, HEADER_TIMESTAMP)
        or header_get(headers, 'X-Mgmt-Timestamp')
        or ''
    ).strip()
    if raw == '':
        raise ValueError('missing timestamp')
    return int(raw)


def _run_openssl(args, input_bytes=None, extra_env=None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        ['openssl', *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or b'').decode('utf-8', errors='replace').strip()
        raise RuntimeError(err or 'openssl command failed')
    return proc.stdout


# OpenSSL `enc -pbkdf2 -iter 200000 -md sha256` compatible wrap. AES is still
# performed by openssl enc -K/-iv so OpenSSL 1.0.2 (Amazon Linux 2) works.
OPENSSL_ENC_MAGIC = b'Salted__'
OPENSSL_PBKDF2_ITER = 200000


def _aes256_cbc(data, key, iv, encrypt):
    args = ['enc', '-aes-256-cbc', '-K', key.hex(), '-iv', iv.hex()]
    if not encrypt:
        args.append('-d')
    return _run_openssl(args, input_bytes=data)


def encrypt_token_pbkdf2(token, secret, iterations=OPENSSL_PBKDF2_ITER):
    if isinstance(token, str):
        token = token.encode('utf-8')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    salt = os.urandom(8)
    dk = hashlib.pbkdf2_hmac('sha256', secret, salt, iterations, dklen=48)
    ct = _aes256_cbc(token, dk[:32], dk[32:], True)
    return base64.b64encode(OPENSSL_ENC_MAGIC + salt + ct).decode('ascii')


def decrypt_token_pbkdf2(ciphertext, secret, iterations=OPENSSL_PBKDF2_ITER):
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    raw = base64.b64decode(str(ciphertext or '').encode('ascii'))
    if not raw.startswith(OPENSSL_ENC_MAGIC) or len(raw) < 16:
        raise ValueError('invalid token ciphertext')
    salt, ct = raw[8:16], raw[16:]
    dk = hashlib.pbkdf2_hmac('sha256', secret, salt, iterations, dklen=48)
    pt = _aes256_cbc(ct, dk[:32], dk[32:], False)
    return pt.decode('utf-8')


def generate_keypair(key_path, pub_path):
    """Create an ECDSA P-256 key pair atomically. Never overwrites key_path.

    key_path only ever appears with complete key material: generation happens in
    a temp file that is linked into place, so a failed or killed run leaves no
    key file at all instead of a zero-byte placeholder that would make the
    identity permanently unusable. link() keeps the no-overwrite guarantee — it
    fails if the name already exists.
    """
    key_path = Path(key_path)
    pub_path = Path(pub_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    _discard_empty_key(key_path)
    if key_path.exists():
        raise FileExistsError(str(key_path))
    fd, tmp_key = tempfile.mkstemp(prefix=key_path.name + '.', suffix='.tmp', dir=str(key_path.parent))
    os.close(fd)
    fd, tmp_pub = tempfile.mkstemp(prefix=pub_path.name + '.', suffix='.tmp', dir=str(key_path.parent))
    os.close(fd)
    try:
        os.chmod(tmp_key, 0o600)
        _run_openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', tmp_key])
        os.chmod(tmp_key, 0o600)
        pub_pem = canonicalize_pubkey_from_private(tmp_key)
        Path(tmp_pub).write_text(pub_pem, encoding='utf-8')
        os.chmod(tmp_pub, 0o644)
        # Claim the final key path last: a loser of this race must not publish
        # its public key over the winner's.
        _link_exclusive(tmp_key, key_path)
        os.replace(tmp_pub, pub_path)
        os.chmod(key_path, 0o600)
    finally:
        for tmp in (tmp_key, tmp_pub):
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


def _discard_empty_key(key_path):
    """Drop a zero-byte key file left behind by an interrupted older run.

    A complete private key is never empty, so a zero-length file is a stale
    placeholder rather than an identity: keeping it would block regeneration
    forever. Anything with content is left alone and still refuses overwrite.
    """
    try:
        if key_path.is_file() and key_path.stat().st_size == 0:
            key_path.unlink()
    except OSError:
        pass


def _link_exclusive(tmp_path, final_path):
    """Publish tmp_path as final_path without ever overwriting or truncating."""
    try:
        os.link(tmp_path, final_path)
        return
    except FileExistsError as exc:
        raise FileExistsError(str(final_path)) from exc
    except OSError:
        # Filesystem without hard links: create exclusively and write in one go.
        pass
    data = Path(tmp_path).read_bytes()
    try:
        fd = os.open(str(final_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(str(final_path)) from exc
    try:
        os.write(fd, data)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(final_path)
        except OSError:
            pass
        raise
    os.close(fd)


def canonicalize_pubkey_from_private(key_path):
    out = _run_openssl(['ec', '-in', str(key_path), '-pubout'])
    text = out.decode('utf-8')
    return canonicalize_pubkey_pem(text)


def canonicalize_pubkey_pem(pem):
    text = str(pem or '').replace('\r\n', '\n').strip() + '\n'
    if len(text) > MAX_PUBKEY_PEM_LEN:
        raise ValueError('public key is too large')
    if 'PRIVATE KEY' in text.upper():
        raise ValueError('private key material is not allowed')
    if not text.startswith('-----BEGIN PUBLIC KEY-----'):
        raise ValueError('public key must be a PUBLIC KEY PEM')
    fd, tmp_in = tempfile.mkstemp(prefix='frp-pubkey.', suffix='.pem')
    os.close(fd)
    try:
        os.chmod(tmp_in, 0o600)
        Path(tmp_in).write_text(text, encoding='utf-8')
        out = _run_openssl(['pkey', '-pubin', '-in', tmp_in, '-pubout'])
        canon = out.decode('utf-8').replace('\r\n', '\n')
        if not canon.endswith('\n'):
            canon += '\n'
        _assert_p256_public(tmp_in)
        return canon
    finally:
        try:
            os.unlink(tmp_in)
        except OSError:
            pass


def _assert_p256_public(pub_path):
    text = _run_openssl(['ec', '-pubin', '-in', str(pub_path), '-text', '-noout']).decode('utf-8')
    lowered = text.lower()
    # OpenSSL 1.0.2 labels EC key size as "Private-Key: (256 bit)" even for
    # public-only PEMs. Reject only when the private scalar is present.
    if '\npriv:' in lowered or lowered.startswith('priv:'):
        raise ValueError('public key rejected')
    if 'nist curve: p-256' not in lowered and 'asn1 oid: prime256v1' not in lowered:
        raise ValueError('management public key must be ECDSA P-256')


def pubkey_der(pem):
    canon = canonicalize_pubkey_pem(pem)
    fd, tmp_in = tempfile.mkstemp(prefix='frp-pubkey.', suffix='.pem')
    os.close(fd)
    try:
        os.chmod(tmp_in, 0o600)
        Path(tmp_in).write_text(canon, encoding='utf-8')
        return _run_openssl(['pkey', '-pubin', '-in', tmp_in, '-outform', 'DER'])
    finally:
        try:
            os.unlink(tmp_in)
        except OSError:
            pass


def pubkey_fingerprint(pem):
    return hashlib.sha256(pubkey_der(pem)).hexdigest()


def fingerprint_display(fingerprint_hex):
    text = str(fingerprint_hex or '').strip().lower()
    if not text:
        return ''
    return 'sha256:' + text[:16]


def validate_private_key(key_path):
    key_path = Path(key_path)
    if not key_path.is_file():
        raise ValueError('management identity is missing')
    mode = key_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ValueError('management identity key permissions are too open (expected 0600)')
    pem = key_path.read_text(encoding='utf-8')
    if 'BEGIN' not in pem or 'PRIVATE KEY' not in pem.upper() and 'EC PRIVATE KEY' not in pem.upper():
        if 'PRIVATE KEY' not in pem.upper():
            raise ValueError('management identity key is not a private key PEM')
    if 'BEGIN PUBLIC KEY' in pem and 'PRIVATE KEY' not in pem.upper():
        raise ValueError('management identity key is not a private key PEM')
    canonicalize_pubkey_from_private(key_path)
    return True


def sign_message(key_path, message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    fd, tmp_sig = tempfile.mkstemp(prefix='frp-sig.', suffix='.bin')
    os.close(fd)
    try:
        os.chmod(tmp_sig, 0o600)
        _run_openssl(
            ['dgst', '-sha256', '-sign', str(key_path), '-out', tmp_sig],
            input_bytes=message,
        )
        sig = Path(tmp_sig).read_bytes()
        if not sig:
            raise RuntimeError('empty signature')
        return base64.b64encode(sig).decode('ascii')
    finally:
        try:
            os.unlink(tmp_sig)
        except OSError:
            pass


def verify_signature(pub_pem, message, signature_b64):
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        raw = str(signature_b64 or '').strip()
        if not raw:
            raise ValueError('malformed signature')
        sig = base64.b64decode(raw)
    except Exception as exc:
        raise ValueError('malformed signature') from exc
    if not sig:
        raise ValueError('malformed signature')
    canon = canonicalize_pubkey_pem(pub_pem)
    fd_pub, tmp_pub = tempfile.mkstemp(prefix='frp-pub.', suffix='.pem')
    os.close(fd_pub)
    fd_sig, tmp_sig = tempfile.mkstemp(prefix='frp-sig.', suffix='.bin')
    os.close(fd_sig)
    try:
        os.chmod(tmp_pub, 0o600)
        os.chmod(tmp_sig, 0o600)
        Path(tmp_pub).write_text(canon, encoding='utf-8')
        Path(tmp_sig).write_bytes(sig)
        proc = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', tmp_pub, '-signature', tmp_sig],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        out = (proc.stdout or b'').decode('utf-8', errors='replace')
        if proc.returncode != 0 or 'Verified OK' not in out:
            return False
        return True
    finally:
        for tmp in (tmp_pub, tmp_sig):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def verify_signed_mgmt_request(
    pub_pem,
    machine_id,
    headers,
    body,
    *,
    op,
    method=None,
    path=None,
    now=None,
    max_skew=MGMT_MAX_CLOCK_SKEW,
):
    """Verify timestamp, nonce syntax, operation binding, body hash, and ECDSA signature.

    Does not look up enrollment status or consume the nonce store.
    Returns (error_message_or_None, ts, nonce).
    """
    try:
        ts = parse_mgmt_timestamp(headers)
    except Exception:
        return 'invalid timestamp', None, None
    nonce = str(header_get(headers, HEADER_NONCE) or '').strip().lower()
    signature = str(header_get(headers, HEADER_SIGNATURE) or '').strip()
    if not signature:
        return 'missing signature', None, None
    if now is None:
        now = int(time.time())
    if abs(int(now) - ts) > int(max_skew):
        return 'request timestamp outside allowed window', None, None
    if not MGMT_NONCE_RE.fullmatch(nonce or ''):
        return 'invalid nonce', None, None
    message = signed_message(
        machine_id, body, ts, nonce, op=op, method=method, path=path
    )
    try:
        ok = verify_signature(pub_pem, message, signature)
    except ValueError as exc:
        return str(exc), None, None
    if not ok:
        return 'invalid signature', None, None
    return None, ts, nonce


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='FRP client management identity helpers')
    sub = parser.add_subparsers(dest='cmd', required=True)
    gen = sub.add_parser('gen-key')
    gen.add_argument('key')
    gen.add_argument('pub')
    pub = sub.add_parser('pub')
    pub.add_argument('key')
    fp = sub.add_parser('fingerprint')
    fp.add_argument('pub')
    sign = sub.add_parser('sign')
    sign.add_argument('key')
    ver = sub.add_parser('verify')
    ver.add_argument('pub')
    ver.add_argument('signature')
    chk = sub.add_parser('check-key')
    chk.add_argument('key')
    der = sub.add_parser('derive-mac')
    der.add_argument('machine_id')
    sub.add_parser('encrypt-token')
    sub.add_parser('decrypt-token')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.cmd == 'gen-key':
        generate_keypair(args.key, args.pub)
        return 0
    if args.cmd == 'pub':
        sys.stdout.write(canonicalize_pubkey_from_private(args.key))
        return 0
    if args.cmd == 'fingerprint':
        pem = Path(args.pub).read_text(encoding='utf-8')
        sys.stdout.write(pubkey_fingerprint(pem) + '\n')
        return 0
    if args.cmd == 'sign':
        message = sys.stdin.buffer.read()
        sys.stdout.write(sign_message(args.key, message))
        return 0
    if args.cmd == 'verify':
        message = sys.stdin.buffer.read()
        pem = Path(args.pub).read_text(encoding='utf-8')
        if verify_signature(pem, message, args.signature):
            return 0
        return 1
    if args.cmd == 'check-key':
        validate_private_key(args.key)
        return 0
    if args.cmd == 'derive-mac':
        secret = os.environ.get('MGMT_ENROLL_SECRET', '')
        if not secret:
            print('ERROR: MGMT_ENROLL_SECRET is not set', file=sys.stderr)
            return 1
        sys.stdout.write(derive_mac_key(secret, args.machine_id))
        return 0
    if args.cmd in ('encrypt-token', 'decrypt-token'):
        secret = os.environ.get('FRP_ENROLL_SECRET', '')
        if not secret:
            print('ERROR: FRP_ENROLL_SECRET is not set', file=sys.stderr)
            return 1
        payload = sys.stdin.read()
        if args.cmd == 'encrypt-token':
            sys.stdout.write(encrypt_token_pbkdf2(payload, secret))
        else:
            sys.stdout.write(decrypt_token_pbkdf2(payload.strip(), secret))
        return 0
    return 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except FileExistsError as exc:
        print(f'ERROR: identity already exists: {exc}', file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)
