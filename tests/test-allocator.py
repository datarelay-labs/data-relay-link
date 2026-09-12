#!/usr/bin/env python3
"""Allocator tests for generic multi-service enrollment (schema v2)."""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
import importlib.util
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]


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


def hmac_hex(secret, message):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


class Env:
    def __init__(self, port_start=18000, port_end=18020):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = self.root / 'registry.json'
        self.token = self.root / 'server_token'
        self.enrollments = self.root / 'enrollments'
        self.enrollments.mkdir()
        self.token.write_text('test-frp-token-do-not-use\n')
        self.token.chmod(0o600)
        self.cfg = self.root / 'config.json'
        cfg = {
            'public_ip': '203.0.113.10',
            'control_port': 443,
            'port_start': port_start,
            'port_end': port_end,
            'listen_host': '127.0.0.1',
            'listen_port': 6099,
            'registry_file': str(self.registry),
            'enrollments_dir': str(self.enrollments),
            'token_file': str(self.token),
        }
        self.cfg.write_text(json.dumps(cfg, indent=2) + '\n')
        MOD.atomic_write_json(self.registry, MOD.empty_registry())
        self.allocator = MOD.Allocator(str(self.cfg))
        MOD.port_is_available = lambda port: True

    def cleanup(self):
        self.tmp.cleanup()

    def add_enrollment(self, enrollment_id='aabbccddeeff0011', secret='secret-aabbccddeeff0011', ttl=600, note='', label=''):
        now = int(time.time())
        record = {
            'id': enrollment_id,
            'secret': secret,
            'created_at': MOD.utc_now_iso(),
            'expires_at': now + ttl,
            'bound_machine_id': None,
            'used_at': None,
        }
        if note:
            record['note'] = note
        if label:
            record['label'] = label
        path = self.enrollments / f'{enrollment_id}.json'
        MOD.atomic_write_json(path, record)
        return enrollment_id, secret

    def enroll(self, services, machine_id='machine-a', hostname='dev-dp-mirror',
               enrollment_id=None, secret=None, timestamp=None, headers=None, peer_host=None):
        if enrollment_id is None:
            enrollment_id, secret = self.add_enrollment()
        body = json.dumps({
            'machine_id': machine_id,
            'hostname': hostname,
            'services': services,
        }, separators=(',', ':')).encode()
        ts = str(timestamp if timestamp is not None else int(time.time()))
        sig = hmac_hex(secret, ts + '\n' + body.decode())
        return self.allocator.enroll(
            enrollment_id, ts, sig, body, headers=headers or {}, peer_host=peer_host
        )

    def load_state(self):
        return json.loads(self.registry.read_text())


def svc(sid, local_ip='127.0.0.1', local_port=22, preset='custom', name=None, ssh_user=None):
    item = {
        'id': sid,
        'name': name or sid,
        'protocol': 'tcp',
        'local_ip': local_ip,
        'local_port': local_port,
        'preset': preset,
    }
    if preset == 'ssh':
        item['ssh_user'] = ssh_user or 'aella'
    return item


def ports_from_response(resp):
    return {item['id']: item['remote_port'] for item in resp['services']}


def case_a_single_ssh():
    env = Env()
    try:
        code, result = env.enroll([svc('ssh', local_port=22, preset='ssh')])
        if code != 200:
            fail('CASE A', result)
        ports = ports_from_response(result)
        if set(ports) != {'ssh'} or not (18000 <= ports['ssh'] <= 18020):
            fail('CASE A', ports)
        state = env.load_state()
        if state.get('schema_version') != 2:
            fail('CASE A schema')
        client = next(iter(state['clients'].values()))
        if 'ssh_port' in client or 'https_port' in client:
            fail('CASE A legacy fields')
        if client['services']['ssh']['remote_port'] != ports['ssh']:
            fail('CASE A stored port')
        pass_('CASE A single SSH')
    finally:
        env.cleanup()


def case_b_no_ssh():
    env = Env()
    try:
        code, result = env.enroll([svc('grafana', local_port=3000, preset='custom', name='Grafana')])
        if code != 200:
            fail('CASE B', result)
        ports = ports_from_response(result)
        if set(ports) != {'grafana'}:
            fail('CASE B', ports)
        pass_('CASE B no SSH')
    finally:
        env.cleanup()


def case_c_multiple():
    env = Env()
    try:
        services = [
            svc('ssh', local_port=22, preset='ssh'),
            svc('grafana', local_port=3000, name='Grafana'),
            svc('admin', local_ip='192.168.122.2', local_port=443, preset='https', name='Web Admin'),
            svc('api', local_port=8080, name='Internal API'),
        ]
        code, result = env.enroll(services)
        if code != 200:
            fail('CASE C', result)
        ports = ports_from_response(result)
        if set(ports) != {'ssh', 'grafana', 'admin', 'api'}:
            fail('CASE C ids', ports)
        if len(set(ports.values())) != 4:
            fail('CASE C unique ports', ports)
        pass_('CASE C multiple services')
    finally:
        env.cleanup()


def case_d_persistent():
    env = Env()
    try:
        first = [
            svc('ssh', local_port=22, preset='ssh'),
            svc('grafana', local_port=3000, name='Grafana'),
        ]
        code, result = env.enroll(first, machine_id='machine-persist')
        if code != 200:
            fail('CASE D first', result)
        original = ports_from_response(result)
        eid, secret = env.add_enrollment('bbccddeeff001122', 'secret-bbccddeeff001122')
        code, result = env.enroll(first, machine_id='machine-persist', enrollment_id=eid, secret=secret)
        if code != 200:
            fail('CASE D second', result)
        again = ports_from_response(result)
        if original != again:
            fail('CASE D ports changed', (original, again))
        pass_('CASE D persistent service ports')
    finally:
        env.cleanup()


def case_e_local_target_change():
    env = Env()
    try:
        code, result = env.enroll([svc('grafana', local_ip='127.0.0.1', local_port=3000)])
        if code != 200:
            fail('CASE E first', result)
        original = ports_from_response(result)['grafana']
        eid, secret = env.add_enrollment('ccddeeff00112233', 'secret-ccddeeff00112233')
        code, result = env.enroll(
            [svc('grafana', local_ip='10.0.0.20', local_port=3000)],
            enrollment_id=eid, secret=secret,
        )
        if code != 200:
            fail('CASE E second', result)
        if ports_from_response(result)['grafana'] != original:
            fail('CASE E port reallocated')
        stored = next(iter(env.load_state()['clients'].values()))['services']['grafana']
        if stored['local_ip'] != '10.0.0.20' or stored['remote_port'] != original:
            fail('CASE E metadata', stored)
        pass_('CASE E local target change preserves port')
    finally:
        env.cleanup()


def case_f_add_later():
    env = Env()
    try:
        code, result = env.enroll([svc('ssh', preset='ssh')])
        if code != 200:
            fail('CASE F first', result)
        ssh_port = ports_from_response(result)['ssh']
        eid, secret = env.add_enrollment('ddeeff0011223344', 'secret-ddeeff0011223344')
        code, result = env.enroll(
            [svc('ssh', preset='ssh'), svc('grafana', local_port=3000, name='Grafana')],
            enrollment_id=eid, secret=secret,
        )
        if code != 200:
            fail('CASE F second', result)
        ports = ports_from_response(result)
        if ports['ssh'] != ssh_port:
            fail('CASE F ssh port changed')
        if ports['grafana'] == ssh_port:
            fail('CASE F grafana reused ssh')
        pass_('CASE F add service later')
    finally:
        env.cleanup()


def case_g_duplicate():
    env = Env()
    try:
        code, result = env.enroll([svc('ssh', preset='ssh'), svc('ssh', preset='ssh')])
        if code != 400 or 'duplicate' not in str(result.get('error', '')).lower():
            fail('CASE G', result)
        pass_('CASE G duplicate service id')
    finally:
        env.cleanup()


def case_g2_case_insensitive_id():
    env = Env()
    try:
        code, result = env.enroll([
            {**svc('ssh', preset='ssh'), 'id': 'ssh'},
            {**svc('ssh', preset='ssh'), 'id': 'SSH'},
        ])
        if code != 400 or 'duplicate' not in str(result.get('error', '')).lower():
            fail('CASE G2', result)
        pass_('CASE G2 case-insensitive duplicate service id')
    finally:
        env.cleanup()


def case_h_invalid_id():
    env = Env()
    try:
        bad = [
            {**svc('ssh', preset='ssh'), 'id': 'SSH'},
            {**svc('bad', local_port=1), 'id': 'has space'},
            {**svc('bad', local_port=1), 'id': '../etc'},
            {**svc('bad', local_port=1), 'id': ''},
            {**svc('bad', local_port=1), 'id': 'a' * 64},
        ]
        # uppercase SSH is lowercased by normalize, so it becomes valid 'ssh'
        code, result = env.enroll([{**svc('x', local_port=1), 'id': 'has space'}])
        if code != 400:
            fail('CASE H space', result)
        eid, secret = env.add_enrollment('eeff001122334455', 'secret-eeff001122334455')
        code, result = env.enroll([{**svc('x', local_port=1), 'id': 'bad/id'}], enrollment_id=eid, secret=secret)
        if code != 400:
            fail('CASE H slash', result)
        eid, secret = env.add_enrollment('ff00112233445566', 'secret-ff00112233445566')
        code, result = env.enroll([{**svc('x', local_port=1), 'id': ''}], enrollment_id=eid, secret=secret)
        if code != 400:
            fail('CASE H empty', result)
        eid, secret = env.add_enrollment('0011223344556677', 'secret-0011223344556677')
        code, result = env.enroll([{**svc('x', local_port=1), 'id': 'a' * 64}], enrollment_id=eid, secret=secret)
        if code != 400:
            fail('CASE H long', result)
        pass_('CASE H invalid service id')
    finally:
        env.cleanup()


def case_i_invalid_port():
    env = Env()
    try:
        for value in (0, -1, 65536, 'abc'):
            eid, secret = env.add_enrollment(
                hashlib.sha256(str(value).encode()).hexdigest()[:16],
                'secret-' + hashlib.sha256(str(value).encode()).hexdigest()[:16],
            )
            item = svc('grafana', local_port=3000)
            item['local_port'] = value
            code, result = env.enroll([item], enrollment_id=eid, secret=secret)
            if code != 400:
                fail(f'CASE I {value}', result)
        pass_('CASE I invalid local port')
    finally:
        env.cleanup()


def case_j_exhaustion():
    env = Env(port_start=18000, port_end=18001)
    try:
        code, result = env.enroll([
            svc('ssh', preset='ssh'),
            svc('grafana', local_port=3000),
        ], machine_id='machine-full')
        if code != 200:
            fail('CASE J setup', result)
        before = env.load_state()
        eid, secret = env.add_enrollment('1122334455667788', 'secret-1122334455667788')
        code, result = env.enroll(
            [svc('extra', local_port=9)],
            machine_id='machine-other',
            enrollment_id=eid,
            secret=secret,
        )
        if code != 500 or result.get('error_class') != 'PORT_RANGE_EXHAUSTED':
            fail('CASE J exhaustion', result)
        if 'no free ports' not in str(result.get('error', '')).lower():
            fail('CASE J generic message', result)
        # Detailed exception text must stay in the server log, not the API body.
        if 'No available FRP service ports' in str(result.get('error', '')):
            fail('CASE J leaked internal exception text', result)
        after = env.load_state()
        if after != before:
            fail('CASE J registry mutated')
        pass_('CASE J port exhaustion')
    finally:
        env.cleanup()


def case_k_concurrent():
    env = Env(port_start=18100, port_end=18120)
    try:
        def worker(i):
            eid = f'{i:016x}'
            secret = f'secret-{eid}'
            env.add_enrollment(eid, secret)
            code, result = env.enroll(
                [svc('app', local_port=8080 + i)],
                machine_id=f'machine-{i}',
                hostname=f'host-{i}',
                enrollment_id=eid,
                secret=secret,
            )
            return code, result

        ports = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(worker, i) for i in range(16)]
            for fut in as_completed(futures):
                code, result = fut.result()
                if code != 200:
                    fail('CASE K enroll', result)
                ports.append(result['services'][0]['remote_port'])
        if len(ports) != len(set(ports)):
            fail('CASE K duplicate ports', ports)
        if len(ports) != 16:
            fail('CASE K count', ports)
        pass_('CASE K concurrent enrollment')
    finally:
        env.cleanup()


def case_omitted_service_not_released():
    env = Env()
    try:
        code, result = env.enroll([
            svc('ssh', preset='ssh'),
            svc('grafana', local_port=3000),
            svc('api', local_port=8080),
        ], machine_id='machine-keep')
        if code != 200:
            fail('reserved first', result)
        original = ports_from_response(result)
        eid, secret = env.add_enrollment('2233445566778899', 'secret-2233445566778899')
        code, result = env.enroll(
            [svc('ssh', preset='ssh'), svc('grafana', local_port=3000)],
            machine_id='machine-keep',
            enrollment_id=eid,
            secret=secret,
        )
        if code != 200:
            fail('reserved second', result)
        if 'api' in ports_from_response(result):
            fail('reserved api still active in response')
        stored = env.load_state()['clients']['machine-keep']['services']
        if stored['api']['remote_port'] != original['api']:
            fail('reserved api port lost')
        if stored['api'].get('enabled') is not False:
            fail('reserved api should be disabled')
        used = env.allocator.used_ports(env.load_state())
        if original['api'] not in used:
            fail('reserved api port reusable')
        pass_('omitted service keeps reserved port')
    finally:
        env.cleanup()


def case_v1_registry_rejected():
    env = Env()
    try:
        env.registry.write_text(json.dumps({
            'reserved': [],
            'clients': {
                'old': {'hostname': 'legacy', 'ssh_port': 6002, 'https_port': None},
            },
        }) + '\n')
        try:
            env.allocator.load_registry()
            fail('v1 registry should raise')
        except MOD.RegistrySchemaError as exc:
            if 'version 1' not in str(exc):
                fail('v1 message', exc)
        pass_('v1 registry rejected')
    finally:
        env.cleanup()


def case_future_schema_rejected():
    env = Env()
    try:
        env.registry.write_text(json.dumps({
            'schema_version': 3,
            'reserved': [],
            'clients': {},
        }) + '\n')
        try:
            env.allocator.load_registry()
            fail('schema 3 should raise')
        except MOD.RegistrySchemaError as exc:
            if 'version 3' not in str(exc):
                fail('schema 3 message', exc)
        pass_('future schema rejected')
    finally:
        env.cleanup()


def case_malformed_registry_rejected():
    env = Env()
    try:
        env.registry.write_text('{not json')
        try:
            env.allocator.load_registry()
            fail('malformed registry should raise')
        except MOD.RegistrySchemaError:
            pass
        pass_('malformed registry rejected')
    finally:
        env.cleanup()


def case_duplicate_port_rejected():
    env = Env()
    try:
        env.registry.write_text(json.dumps({
            'schema_version': 2,
            'reserved': [],
            'clients': {
                'a': {'hostname': 'a', 'services': {
                    'ssh': {'remote_port': 18000, 'enabled': True, 'local_ip': '127.0.0.1', 'local_port': 22},
                }},
                'b': {'hostname': 'b', 'services': {
                    'web': {'remote_port': 18000, 'enabled': True, 'local_ip': '127.0.0.1', 'local_port': 80},
                }},
            },
        }) + '\n')
        try:
            env.allocator.load_registry()
            fail('duplicate ports should raise')
        except MOD.RegistrySchemaError as exc:
            if 'duplicate public port' not in str(exc):
                fail('duplicate port message', exc)
        before = env.registry.read_text()
        code, result = env.enroll([svc('ssh', preset='ssh')])
        if code != 500 or result.get('error_class') != 'REGISTRY_INVALID':
            fail('duplicate port enroll', result)
        if env.registry.read_text() != before:
            fail('duplicate port registry rewritten')
        pass_('duplicate port ownership fail-closed')
    finally:
        env.cleanup()


def case_registry_write_failure():
    env = Env()
    try:
        code, result = env.enroll([svc('ssh', preset='ssh')], machine_id='machine-write')
        if code != 200:
            fail('write-fail setup', result)
        before = env.registry.read_bytes()

        def boom(path):
            if str(path).endswith('registry.json'):
                raise OSError('simulated registry write failure')

        original = MOD._test_before_registry_write
        MOD._test_before_registry_write = boom
        try:
            eid, secret = env.add_enrollment('9988776655443322', 'secret-9988776655443322')
            code, result = env.enroll(
                [svc('ssh', preset='ssh'), svc('grafana', local_port=3000)],
                machine_id='machine-write',
                enrollment_id=eid,
                secret=secret,
            )
        finally:
            MOD._test_before_registry_write = original
        if code != 500 or result.get('error_class') != 'SERVER_MUTATION_FAILED':
            fail('write-fail response', result)
        if env.registry.read_bytes() != before:
            fail('write-fail mutated registry')
        pass_('registry write failure leaves previous registry')
    finally:
        env.cleanup()


def case_lost_response_retry():
    env = Env()
    try:
        first = [svc('ssh', preset='ssh'), svc('grafana', local_port=3000)]
        code, result = env.enroll(first, machine_id='machine-lost')
        if code != 200:
            fail('lost-response first', result)
        original = ports_from_response(result)
        eid, secret = env.add_enrollment('aabbccddeeff0099', 'secret-aabbccddeeff0099')
        code, result = env.enroll(
            first, machine_id='machine-lost', enrollment_id=eid, secret=secret
        )
        if code != 200:
            fail('lost-response retry', result)
        if ports_from_response(result) != original:
            fail('lost-response ports changed', (original, ports_from_response(result)))
        state = env.load_state()
        services = state['clients']['machine-lost']['services']
        if set(services) != {'ssh', 'grafana'}:
            fail('lost-response duplicate services', services)
        pass_('lost response retry is idempotent')
    finally:
        env.cleanup()


def case_range_6000_exhaustion():
    env = Env(port_start=6000, port_end=6002)
    try:
        for i, sid in enumerate(('ssh', 'web', 'api')):
            eid, secret = env.add_enrollment(f'{i+1:016x}', f'secret-{i+1:016x}')
            code, result = env.enroll(
                [svc(sid, local_port=20 + i)],
                machine_id=f'machine-r{i}',
                hostname=f'host-r{i}',
                enrollment_id=eid,
                secret=secret,
            )
            if code != 200:
                fail(f'range fill {sid}', result)
        before = env.load_state()
        eid, secret = env.add_enrollment('0000000000000099', 'secret-range-extra')
        code, result = env.enroll(
            [svc('extra', local_port=9)],
            machine_id='machine-extra',
            enrollment_id=eid,
            secret=secret,
        )
        if code != 500 or result.get('error_class') != 'PORT_RANGE_EXHAUSTED':
            fail('range 6000-6002 exhaustion', result)
        if env.load_state() != before:
            fail('range exhaustion mutated registry')
        if 'machine-extra' in env.load_state()['clients']:
            fail('range exhaustion created partial client')
        pass_('range 6000-6002 exhaustion')
    finally:
        env.cleanup()


def case_admin_metadata_and_source_ip():
    env = Env()
    try:
        eid, secret = env.add_enrollment(
            enrollment_id='feedfacefeedface',
            secret='secret-feedfacefeedface',
            note='Seoul office groupware server',
            label='seoul-groupware',
        )
        code, result = env.enroll(
            [svc('ssh', preset='ssh')],
            machine_id='aabbccddeeff00112233445566778899',
            hostname='aella',
            enrollment_id=eid,
            secret=secret,
            peer_host='203.0.113.50',
            headers={'X-Forwarded-For': '198.51.100.9'},
        )
        if code != 200:
            fail('metadata enroll', result)
        client = env.load_state()['clients']['aabbccddeeff00112233445566778899']
        if client.get('label') != 'seoul-groupware':
            fail('seed label', client)
        if client.get('note') != 'Seoul office groupware server':
            fail('seed note', client)
        if client.get('hostname') != 'aella':
            fail('hostname', client)
        if client.get('last_source_ip') != '203.0.113.50':
            fail('direct peer IP ignored XFF', client)
        port = client['services']['ssh']['remote_port']
        mgmt = client.get('mgmt_status')
        eid2, secret2 = env.add_enrollment(
            enrollment_id='cafebabecafebabe',
            secret='secret-cafebabecafebabe',
            note='should-not-overwrite',
            label='should-not-overwrite',
        )
        code, result = env.enroll(
            [svc('ssh', preset='ssh')],
            machine_id='aabbccddeeff00112233445566778899',
            hostname='aella-renamed',
            enrollment_id=eid2,
            secret=secret2,
            peer_host='127.0.0.1',
            headers={'X-Forwarded-For': '198.51.100.20'},
        )
        if code != 200:
            fail('reenroll', result)
        client = env.load_state()['clients']['aabbccddeeff00112233445566778899']
        if client.get('label') != 'seoul-groupware':
            fail('reenroll overwrote label', client)
        if client.get('note') != 'Seoul office groupware server':
            fail('reenroll overwrote note', client)
        if client.get('hostname') != 'aella-renamed':
            fail('observed hostname not updated', client)
        if client['services']['ssh']['remote_port'] != port:
            fail('port changed')
        if client.get('mgmt_status') != mgmt:
            fail('mgmt changed')
        if client.get('last_source_ip') != '198.51.100.20':
            fail('loopback trusted XFF', client)
        pass_('admin metadata preserved on re-enroll')
        pass_('source IP trust boundary')
    finally:
        env.cleanup()


def case_unreadable_host_version_fallback():
    """0700 host version dir must not crash healthz; fall back to repo VERSION."""
    import unittest.mock

    expected = ''
    for line in (ROOT / 'VERSION').read_text(encoding='utf-8').splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() == 'PROJECT_VERSION':
            expected = value.strip()
            break
    if not expected:
        fail('unreadable version fixture', 'missing PROJECT_VERSION')

    real_is_file = Path.is_file

    def fake_is_file(self, *args, **kwargs):
        if str(self) == '/etc/drlink/version':
            raise PermissionError(13, 'Permission denied', str(self))
        return real_is_file(self, *args, **kwargs)

    with unittest.mock.patch.object(Path, 'is_file', fake_is_file):
        got = MOD.read_project_version()
    if got != expected:
        fail('unreadable host version fallback', got)
    pass_('unreadable 0700 host version falls back')


def main():
    case_a_single_ssh()
    case_b_no_ssh()
    case_c_multiple()
    case_d_persistent()
    case_e_local_target_change()
    case_f_add_later()
    case_g_duplicate()
    case_g2_case_insensitive_id()
    case_h_invalid_id()
    case_i_invalid_port()
    case_j_exhaustion()
    case_k_concurrent()
    case_omitted_service_not_released()
    case_v1_registry_rejected()
    case_future_schema_rejected()
    case_malformed_registry_rejected()
    case_duplicate_port_rejected()
    case_registry_write_failure()
    case_lost_response_retry()
    case_range_6000_exhaustion()
    case_admin_metadata_and_source_ip()
    case_unreadable_host_version_fallback()
    print()
    print('ALLOCATOR_GENERIC_TESTS=PASS')


if __name__ == '__main__':
    main()
