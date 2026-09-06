#!/usr/bin/env python3
"""Verify a PowerShell-produced ECDSA signature using frp_mgmt_auth.

Inputs may come from CLI flags or a BOM-less UTF-8 JSON file (--from-json)
to avoid Windows PowerShell 5.1 argument quoting breakage on JSON bodies.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'lib'))

import frp_mgmt_auth as MGMT  # noqa: E402


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b'\xef\xbb\xbf'):
        raw = raw[3:]
    return raw.decode('utf-8')


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--from-json', help='JSON file with pubkey_pem, body, ts, nonce, machine_id, sig_b64')
    p.add_argument('--pubkey-pem')
    p.add_argument('--body')
    p.add_argument('--ts', type=int)
    p.add_argument('--nonce')
    p.add_argument('--machine-id')
    p.add_argument('--sig-b64')
    p.add_argument('--op', default='enroll')
    args = p.parse_args(argv)

    if args.from_json:
        data = json.loads(_read_text(Path(args.from_json)))
        pub = data['pubkey_pem']
        body = data['body']
        ts = int(data['ts'])
        nonce = data['nonce']
        machine_id = data['machine_id']
        sig_b64 = data['sig_b64']
        op = data.get('op', args.op)
    else:
        if not all([args.pubkey_pem, args.body, args.ts is not None, args.nonce, args.machine_id, args.sig_b64]):
            print('ERROR: missing required verify arguments', file=sys.stderr)
            return 2
        pub = _read_text(Path(args.pubkey_pem))
        body = args.body
        ts = args.ts
        nonce = args.nonce
        machine_id = args.machine_id
        sig_b64 = args.sig_b64
        op = args.op

    message = MGMT.signed_message(machine_id, body, ts, nonce, op=op)
    ok = MGMT.verify_signature(pub, message, sig_b64)
    if not ok:
        print('VERIFY_FAIL', file=sys.stderr)
        return 1
    print('VERIFY_OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
