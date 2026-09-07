#!/usr/bin/env python3
"""Generate cross-language vectors from lib/frp_mgmt_auth.py for PowerShell tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'lib'))

import frp_mgmt_auth as MGMT  # noqa: E402

OUT = Path(__file__).resolve().parent / 'vectors.json'

SECRET = 'secret-deadbeef0123456789abcdef'
TOKEN = 'frp-token-deadbeef-do-not-use'
MACHINE_ID = 'machine-id-deadbeef01'
BODY = '{"machine_id":"machine-id-deadbeef01","hostname":"win-test","services":[]}'
TS = 1700000000
NONCE = 'ab' * 32


def main():
    key_path = Path(__file__).resolve().parent / 'tmp-key.pem'
    pub_path = Path(__file__).resolve().parent / 'tmp-pub.pem'
    if key_path.exists():
        key_path.unlink()
    if pub_path.exists():
        pub_path.unlink()
    MGMT.generate_keypair(key_path, pub_path)
    pub_pem = pub_path.read_text(encoding='utf-8')
    message = MGMT.signed_message(MACHINE_ID, BODY, TS, NONCE)
    sig = MGMT.sign_message(key_path, message)
    ct = MGMT.encrypt_token_pbkdf2(TOKEN, SECRET)
    mac = MGMT.derive_mac_key(SECRET, MACHINE_ID)
    enroll_sig = MGMT.hmac_hex(SECRET, f'{TS}\n{BODY}')
    canonical_obj = {
        'alg': 'ecdsa-p256-sha256',
        'body_sha256': MGMT.sha256_hex(BODY),
        'machine_id': MACHINE_ID,
        'nonce': NONCE,
        'op': 'enroll',
        'schema': 1,
        'ts': TS,
    }
    vectors = {
        'secret': SECRET,
        'token': TOKEN,
        'token_ciphertext_python': ct,
        'machine_id': MACHINE_ID,
        'body': BODY,
        'ts': TS,
        'nonce': NONCE,
        'signed_message': message,
        'python_signature_b64': sig,
        'python_public_pem': pub_pem,
        # Intentionally omit private PEM from the written fixture so secret-scan
        # and the public repo never track key material. Keys are regenerated
        # each test run and deleted below.
        'derive_mac_key': mac,
        'enrollment_hmac': enroll_sig,
        'canonical_signed_object': MGMT.canonical_json(canonical_obj),
        'canonical_sample': MGMT.canonical_json({'b': 1, 'a': 2, 'z': ['x', 'y'], 'n': None, 't': True}),
    }
    OUT.write_text(json.dumps(vectors, indent=2) + '\n', encoding='utf-8')
    # Keep key material only inside vectors.json for tests; remove loose key files.
    key_path.unlink(missing_ok=True)
    pub_path.unlink(missing_ok=True)
    print(str(OUT))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
