#!/usr/bin/env python3
"""P2.3 management identity: signatures, replay, revocation, no private-key leak."""
import hashlib
import hmac
import json
import sys
import tempfile
import time
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_mod('frp_port_allocator', ROOT / 'server' / 'frp-port-allocator.py')
MGMT = load_mod('frp_mgmt_auth', ROOT / 'lib' / 'frp_mgmt_auth.py')


def pass_(name):
    print(f'PASS {name}')


def fail(name, detail=''):
    print(f'FAIL {name} {detail}'.rstrip(), file=sys.stderr)
    raise SystemExit(1)


def hmac_hex(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = self.root / 'registry.json'
        self.token = self.root / 'server_token'
        self.enrollments = self.root / 'enrollments'
        self.enrollments.mkdir()
        self.keys = self.root / 'keys'
        self.keys.mkdir()
        self.token.write_text('test-enroll-token-do-not-use\n')
        self.token.chmod(0o600)
        self.cfg = self.root / 'config.json'
        self.cfg.write_text(json.dumps({
            'public_ip': '203.0.113.10',
            'control_port': 443,
            'port_start': 18300,
            'port_end': 18320,
            'listen_host': '127.0.0.1',
            'listen_port': 6099,
            'registry_file': str(self.registry),
            'enrollments_dir': str(self.enrollments),
            'token_file': str(self.token),
        }, indent=2) + '\n')
        MOD.atomic_write_json(self.registry, MOD.empty_registry())
        self.allocator = MOD.Allocator(str(self.cfg))
        MOD.port_is_available = lambda port: True
        self.eid = 'abcdef0123456789'
        self.secret = 'enroll-secret-abcdef0123456789'
        now = int(time.time())
        MOD.atomic_write_json(self.enrollments / f'{self.eid}.json', {
            'id': self.eid,
            'secret': self.secret,
            'expires_at': now + 600,
            'bound_machine_id': None,
            'used_at': None,
        })
        self.key = self.keys / 'client-identity.key'
        self.pub = self.keys / 'client-identity.pub'
        MGMT.generate_keypair(self.key, self.pub)
        try:
            MGMT.generate_keypair(self.key, self.pub)
            fail('generate_keypair overwrote an existing key')
        except FileExistsError:
            pass
        self.pub_pem = self.pub.read_text(encoding='utf-8')

    def cleanup(self):
        self.tmp.cleanup()

    def add_enrollment(self, eid, secret, ttl=600):
        now = int(time.time())
        MOD.atomic_write_json(self.enrollments / f'{eid}.json', {
            'id': eid,
            'secret': secret,
            'expires_at': now + ttl,
            'bound_machine_id': None,
            'used_at': None,
        })
        return eid, secret

    def body(self, machine_id='machine-id-p23', extra=None, include_pub=True, services=None):
        payload = {
            'machine_id': machine_id,
            'hostname': 'p23-host',
            'services': services or [{
                'id': 'ssh',
                'name': 'SSH',
                'protocol': 'tcp',
                'local_ip': '127.0.0.1',
                'local_port': 22,
                'preset': 'ssh',
                'ssh_user': 'aella',
            }],
        }
        if include_pub:
            payload['mgmt_pubkey'] = self.pub_pem
            payload['mgmt_alg'] = MGMT.MGMT_ALG
        if extra:
            payload.update(extra)
        return json.dumps(payload, separators=(',', ':')).encode()

    def enroll_hmac(self, body=None, enrollment_id=None, secret=None):
        body = body if body is not None else self.body()
        ts = str(int(time.time()))
        secret = secret if secret is not None else self.secret
        eid = enrollment_id or self.eid
        sig = hmac_hex(secret, ts + '\n' + body.decode())
        return self.allocator.enroll(eid, ts, sig, body)

    def signed_headers(self, body, machine_id='machine-id-p23', ts=None, nonce=None, key=None):
        ts = int(ts if ts is not None else time.time())
        nonce = nonce or MGMT.new_nonce()
        key = key or self.key
        message = MGMT.signed_message(machine_id, body, ts, nonce)
        signature = MGMT.sign_message(key, message)
        return {
            'X-Mgmt-Auth': '1',
            'X-Timestamp': str(ts),
            'X-Mgmt-Nonce': nonce,
            'X-Mgmt-Signature': signature,
        }, ts, nonce, signature

    def enroll_signed(self, body=None, machine_id='machine-id-p23', **kwargs):
        body = body if body is not None else self.body(machine_id=machine_id, include_pub=False)
        headers, ts, nonce, signature = self.signed_headers(body, machine_id=machine_id, **kwargs)
        return self.allocator.enroll('', str(ts), '', body, headers=headers), headers, body

    def load_client(self, machine_id='machine-id-p23'):
        state = json.loads(self.registry.read_text())
        return state['clients'][machine_id]


def dump_has_private(data):
    text = json.dumps(data)
    return 'BEGIN' in text and 'PRIVATE KEY' in text.upper()


def main():
    env = Env()
    try:
        mode = env.key.stat().st_mode & 0o777
        if mode != 0o600:
            fail('private key mode', oct(mode))
        pass_('new key mode 0600')

        code, result = env.enroll_hmac()
        if code != 200:
            fail('enroll with pubkey', result)
        client = env.load_client()
        if client.get('mgmt_status') != 'enrolled':
            fail('status enrolled', client.get('mgmt_status'))
        if not client.get('mgmt_pubkey'):
            fail('pubkey stored')
        if dump_has_private(client) or dump_has_private(result):
            fail('private key leaked into registry/response')
        if 'mgmt_mac_key' in result or env.token.read_text().strip() in json.dumps(result):
            fail('secret leaked in enrollment response')
        if client.get('mgmt_pubkey') != MGMT.canonicalize_pubkey_pem(env.pub_pem):
            fail('stored pubkey mismatch')
        if 'PRIVATE' in (client.get('mgmt_pubkey') or ''):
            fail('stored key is private')
        expected_mac = MGMT.derive_mac_key(env.secret, 'machine-id-p23')
        if client.get('mgmt_mac_key') != expected_mac:
            fail('mac key derivation')
        pass_('enrollment stores public identity only')
        pass_('private key not in registry or response')

        ssh_port = result['services'][0]['remote_port']

        body = env.body(include_pub=False, services=[{
            'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 22, 'preset': 'ssh', 'ssh_user': 'aella',
        }, {
            'id': 'grafana', 'name': 'Grafana', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 3000, 'preset': 'custom',
        }])
        (code, result), headers, signed_body = env.enroll_signed(body)
        if code != 200:
            fail('signed add service', result)
        if 'token_ciphertext' in result:
            fail('signed response included FRP token material')
        received = result.pop('response_hmac')
        expected = MGMT.hmac_hex(expected_mac, MOD.canonical_json(result))
        if not hmac.compare_digest(received, expected):
            fail('signed response hmac')
        result['response_hmac'] = received
        ports = {item['id']: item['remote_port'] for item in result['services']}
        if ports['ssh'] != ssh_port:
            fail('signed add moved ssh port')
        grafana_port = ports['grafana']
        pass_('signed mutation accepted')
        pass_('FRP token not in management response')

        (code, result), _, _ = env.enroll_signed(body)
        if code != 200:
            fail('signed lost-response retry', result)
        retry_ports = {item['id']: item['remote_port'] for item in result['services']}
        if retry_ports['ssh'] != ssh_port or retry_ports['grafana'] != grafana_port:
            fail('signed retry reallocated', retry_ports)
        pass_('signed lost-response retry reuses ports')

        replay_code, replay_result = env.allocator.enroll(
            '', headers['X-Timestamp'], '', signed_body, headers=headers
        )
        if replay_code != 403 or 'replay' not in replay_result.get('error', ''):
            fail('replay', replay_result)
        if replay_result.get('error_class') != 'REPLAY_REJECTED':
            fail('replay class', replay_result)
        pass_('replayed nonce rejected')

        stale_body = env.body(include_pub=False)
        (code, result), _, _ = env.enroll_signed(
            stale_body, ts=int(time.time()) - 10_000
        )
        if code != 403:
            fail('stale timestamp', result)
        pass_('stale timestamp rejected')

        tamper_body = env.body(include_pub=False, extra={'hostname': 'evil'})
        headers, ts, nonce, signature = env.signed_headers(signed_body)
        code, result = env.allocator.enroll('', str(ts), '', tamper_body, headers=headers)
        if code != 403:
            fail('tampered body', result)
        pass_('payload tamper rejected')

        other = env.keys / 'other.key'
        other_pub = env.keys / 'other.pub'
        MGMT.generate_keypair(other, other_pub)
        (code, result), _, _ = env.enroll_signed(env.body(include_pub=False), key=other)
        if code != 403:
            fail('wrong key', result)
        pass_('wrong key rejected')

        headers, ts, nonce, _sig = env.signed_headers(env.body(include_pub=False))
        headers['X-Mgmt-Signature'] = ''
        code, result = env.allocator.enroll(
            '', str(ts), '', env.body(include_pub=False), headers=headers
        )
        if code != 403 or 'missing signature' not in result.get('error', ''):
            fail('missing signature', result)
        pass_('missing signature rejected')

        wrong_id_body = env.body(machine_id='machine-other', include_pub=False)
        headers, ts, nonce, signature = env.signed_headers(
            wrong_id_body, machine_id='machine-other'
        )
        code, result = env.allocator.enroll('', str(ts), '', wrong_id_body, headers=headers)
        if code != 403:
            fail('wrong client identity', result)
        pass_('wrong client identity rejected')

        headers, ts, nonce, signature = env.signed_headers(env.body(include_pub=False))
        headers['X-Mgmt-Signature'] = 'not-a-signature'
        code, result = env.allocator.enroll(
            '', str(ts), '', env.body(include_pub=False), headers=headers
        )
        if code != 403:
            fail('malformed signature', result)
        pass_('malformed signature rejected')

        edit_body = env.body(include_pub=False, services=[{
            'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 2222, 'preset': 'ssh', 'ssh_user': 'aella',
        }, {
            'id': 'grafana', 'name': 'Grafana', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 3000, 'preset': 'custom',
        }])
        headers, ts, nonce, signature = env.signed_headers(edit_body)
        before = env.registry.read_bytes()

        def boom(path):
            if str(path).endswith('registry.json'):
                raise OSError('simulated registry write failure')

        original = MOD._test_before_registry_write
        MOD._test_before_registry_write = boom
        try:
            code, result = env.allocator.enroll('', str(ts), '', edit_body, headers=headers)
        finally:
            MOD._test_before_registry_write = original
        if code != 500:
            fail('nonce write-fail status', result)
        if env.registry.read_bytes() != before:
            fail('nonce write-fail mutated registry')
        code, result = env.allocator.enroll('', str(ts), '', edit_body, headers=headers)
        if code != 200:
            fail('same nonce after failed save', result)
        if env.load_client()['services']['ssh']['local_port'] != 2222:
            fail('retry after write-fail did not apply')
        if env.load_client()['services']['ssh']['remote_port'] != ssh_port:
            fail('retry after write-fail reallocated ssh')
        pass_('failed mutation does not burn nonce')

        # Finding N: nonce persist failure after registry mutation must roll back
        # authority changes and leave the signed request replayable once.
        edit_body = env.body(include_pub=False, services=[{
            'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 2222, 'preset': 'ssh', 'ssh_user': 'aella',
        }, {
            'id': 'grafana', 'name': 'Grafana', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 3000, 'preset': 'custom',
        }])
        headers, ts, nonce, signature = env.signed_headers(edit_body)
        before = env.registry.read_bytes()
        before_client = env.load_client()

        def boom_nonce(path):
            if 'mgmt-nonces.json' in str(path):
                raise OSError('simulated nonce write failure')

        original_nonce = MOD._test_before_nonce_write
        MOD._test_before_nonce_write = boom_nonce
        try:
            code, result = env.allocator.enroll('', str(ts), '', edit_body, headers=headers)
        finally:
            MOD._test_before_nonce_write = original_nonce
        if code not in (403, 500):
            fail('nonce persist-fail status', result)
        if env.registry.read_bytes() != before:
            fail('nonce persist-fail left mutated registry')
        after_client = env.load_client()
        if after_client['services']['ssh']['local_port'] != before_client['services']['ssh']['local_port']:
            fail('nonce persist-fail changed ssh local_port')
        # Same signed request must still apply exactly once after recovery.
        code, result = env.allocator.enroll('', str(ts), '', edit_body, headers=headers)
        if code != 200:
            fail('same nonce after nonce persist-fail', result)
        if env.load_client()['services']['ssh']['local_port'] != 2222:
            fail('retry after nonce persist-fail did not apply')
        # Replay of the same signed request must now be rejected.
        code, result = env.allocator.enroll('', str(ts), '', edit_body, headers=headers)
        if code != 403 or 'replay' not in str(result.get('error', '')).lower():
            fail('replay after successful nonce commit', result)
        pass_('nonce persist failure rolls back mutation')

        env.allocator.load_registry()
        state = json.loads(env.registry.read_text())
        state['clients']['machine-id-p23']['mgmt_status'] = 'revoked'
        state['clients']['machine-id-p23']['mgmt_mac_key'] = None
        MOD.atomic_write_json(env.registry, state)
        (code, result), _, _ = env.enroll_signed(env.body(include_pub=False))
        if code != 403 or 'revoked' not in result.get('error', ''):
            fail('revoked identity', result)
        if result.get('error_class') != 'REVOKED':
            fail('revoked class', result)
        stored = env.load_client()
        if stored['services']['grafana']['remote_port'] != grafana_port:
            fail('revoke released ports')
        if stored['services']['ssh']['remote_port'] != ssh_port:
            fail('revoke released ssh')
        pass_('revoked identity rejected')
        pass_('revocation keeps reservations')

        eid2, secret2 = env.add_enrollment('fedcba9876543210', 'enroll-secret-fedcba9876543210')
        code, result = env.enroll_hmac(env.body(), enrollment_id=eid2, secret=secret2)
        if code != 200:
            fail('re-enroll after revoke', result)
        if env.load_client().get('mgmt_status') != 'enrolled':
            fail('re-enroll status')
        (code, result), _, _ = env.enroll_signed(env.body(include_pub=False, services=[{
            'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp',
            'local_ip': '127.0.0.1', 'local_port': 22, 'preset': 'ssh', 'ssh_user': 'aella',
        }]))
        if code != 200:
            fail('signed after re-enroll', result)
        pass_('re-enroll after revocation')

        other2 = env.keys / 'rotated.key'
        other2_pub = env.keys / 'rotated.pub'
        MGMT.generate_keypair(other2, other2_pub)
        env.pub_pem = other2_pub.read_text(encoding='utf-8')
        eid3, secret3 = env.add_enrollment('0123456789abcdef', 'enroll-secret-0123456789abcdef')
        code, result = env.enroll_hmac(env.body(), enrollment_id=eid3, secret=secret3)
        if code != 200:
            fail('rotate identity', result)
        (code, result), _, _ = env.enroll_signed(env.body(include_pub=False), key=env.key)
        if code != 403:
            fail('old key after rotate', result)
        pass_('old credential invalid after new identity')

        env2 = Env()
        try:
            code, result = env2.enroll_hmac(env2.body(include_pub=False))
            if code != 200:
                fail('legacy enroll', result)
            client = env2.load_client()
            if MOD.Allocator.mgmt_status(client) != 'legacy':
                fail('legacy status', client)
            (code, result), _, _ = env2.enroll_signed(env2.body(include_pub=False))
            if code != 403:
                fail('legacy signed should fail', result)
            pass_('legacy client is not silently trusted')
        finally:
            env2.cleanup()
    finally:
        env.cleanup()

    print()
    print('MGMT_IDENTITY_TEST=PASS')


if __name__ == '__main__':
    main()
