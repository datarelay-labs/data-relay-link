#!/usr/bin/env python3
"""Bootstrap ticket issue/redeem tests. Isolated fixtures only."""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
sys.path.insert(0, str(ROOT / 'lib'))

import importlib.util

spec = importlib.util.spec_from_file_location(
    'frp_port_allocator', ROOT / 'server' / 'frp-port-allocator.py'
)
MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOD)

FAILED = 0


def pass_(name):
    print('PASS', name)


def fail(name, detail=''):
    global FAILED
    FAILED += 1
    print('FAIL', name, detail)


class Env:
    def __init__(self):
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
            'public_host': '203.0.113.10',
            'public_ip': '203.0.113.10',
            'frp_control_public_port': 8443,
            'control_port': 443,
            'port_start': 19000,
            'port_end': 19020,
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

    def ssh_services(self, user='aella', port=22):
        return MOD.normalize_services([{
            'id': 'ssh',
            'name': 'SSH',
            'protocol': 'tcp',
            'local_ip': '127.0.0.1',
            'local_port': port,
            'preset': 'ssh',
            'ssh_user': user,
        }])

    def issue(self, ttl=600, note='fixture', services=None):
        services = services if services is not None else self.ssh_services()
        return self.allocator.issue_bootstrap_ticket(services, ttl, note)

    def redeem(self, ticket, machine_id='machine-a', hostname='host-a'):
        body = json.dumps({
            'ticket': ticket,
            'machine_id': machine_id,
            'hostname': hostname,
        }, separators=(',', ':')).encode()
        return self.allocator.redeem_bootstrap(body)


def test_issue_hashed_and_entropy():
    env = Env()
    try:
        ticket, enroll, record = env.issue()
        parts = ticket.split('.')
        if len(parts) != 3 or parts[0] != 'bt1':
            fail('ticket format', ticket)
            return
        if len(parts[1]) != 16 or len(parts[2]) != 64:
            fail('ticket entropy', 'id=%s secret_len=%s' % (len(parts[1]), len(parts[2])))
            return
        path = env.allocator.bootstrap_path(parts[1])
        stored = json.loads(path.read_text())
        raw = json.dumps(stored)
        if parts[2] in raw or ticket in raw:
            fail('raw ticket stored', raw)
            return
        if stored.get('secret_hash') != MOD.hash_bootstrap_secret(parts[2]):
            fail('secret hash mismatch')
            return
        if 'secret' in stored:
            fail('secret field in ticket record')
            return
        enroll_path = env.allocator.enrollment_path(enroll['id'])
        enroll_stored = json.loads(enroll_path.read_text())
        if enroll_stored.get('secret') != enroll['secret']:
            fail('enrollment secret missing')
            return
        state = env.allocator.load_registry()
        if state.get('clients'):
            fail('create allocated a client')
            return
        if state.get('reserved'):
            fail('create reserved a port')
            return
        mode = oct(path.stat().st_mode & 0o777)
        if mode != '0o600':
            fail('ticket mode', mode)
            return
        pass_('BOOTSTRAP_TICKET_HASHED_AT_REST')
        pass_('BOOTSTRAP_TICKET_ENTROPY')
        pass_('SERVER_CREATION_NO_PORT_RESERVATION')
    finally:
        env.cleanup()


def test_redeem_bind_and_retry():
    env = Env()
    try:
        ticket, enroll, _record = env.issue()
        code, result = env.redeem(ticket, 'machine-a')
        if code != 200:
            fail('first redeem', result)
            return
        if result.get('enrollment_code') != '%s.%s' % (enroll['id'], enroll['secret']):
            fail('enrollment code mismatch')
            return
        if not result.get('services'):
            fail('services missing')
            return
        bound = json.loads(env.allocator.bootstrap_path(ticket.split('.')[1]).read_text())
        if bound.get('bound_machine_id') != 'machine-a':
            fail('not bound', bound)
            return
        code2, result2 = env.redeem(ticket, 'machine-a')
        if code2 != 200:
            fail('same machine retry', result2)
            return
        if result2.get('enrollment_code') != result.get('enrollment_code'):
            fail('retry enrollment changed')
            return
        code3, result3 = env.redeem(ticket, 'machine-b')
        if code3 != 409 or result3.get('error_class') != 'BOOTSTRAP_TICKET_BOUND':
            fail('second machine', '%s %s' % (code3, result3))
            return
        pass_('BOOTSTRAP_TICKET_FIRST_MACHINE_BINDING')
        pass_('BOOTSTRAP_TICKET_SAME_MACHINE_RETRY')
        pass_('BOOTSTRAP_TICKET_SECOND_MACHINE_REJECTED')
    finally:
        env.cleanup()


def test_expired_and_invalid():
    env = Env()
    try:
        ticket, _enroll, _record = env.issue(ttl=1)
        path = env.allocator.bootstrap_path(ticket.split('.')[1])
        rec = json.loads(path.read_text())
        rec['expires_at'] = int(time.time()) - 5
        path.write_text(json.dumps(rec, indent=2) + '\n')
        enroll_path = env.allocator.enrollment_path(json.loads(path.read_text())['enrollment_id'])
        en = json.loads(enroll_path.read_text())
        en['expires_at'] = rec['expires_at']
        enroll_path.write_text(json.dumps(en, indent=2) + '\n')
        code, result = env.redeem(ticket)
        if code != 410 or result.get('error_class') != 'BOOTSTRAP_TICKET_EXPIRED':
            fail('expired', '%s %s' % (code, result))
            return
        state = env.allocator.load_registry()
        if state.get('clients') or state.get('reserved'):
            fail('expired ticket reserved a port')
            return
        pass_('BOOTSTRAP_TICKET_EXPIRED_REJECTED')
        pass_('UNUSED_TICKET_NO_RESERVATION')

        good, _e, _r = env.issue()
        cases = [
            'not-a-ticket',
            'bt1.deadbeefdeadbeef.00',
            'bt1.' + ('a' * 16) + '.' + ('b' * 63),
            'bt1.' + ('a' * 16) + '.' + ('b' * 65),
            'bt1.' + ('z' * 16) + '.' + ('0' * 64),
            'bt1.' + good.split('.')[1] + '.' + ('0' * 64),
            'x' * 200,
            '',
        ]
        for raw in cases:
            code, result = env.redeem(raw)
            if code not in (400, 403) or result.get('error_class') not in (
                'BOOTSTRAP_TICKET_INVALID', 'ZERO_TOUCH_INPUT_INVALID'
            ):
                fail('invalid ticket %r' % raw, '%s %s' % (code, result))
                return
        pass_('BOOTSTRAP_TICKET_INVALID')
    finally:
        env.cleanup()


def test_malformed_json_no_bind():
    env = Env()
    try:
        ticket, _e, _r = env.issue()
        code, result = env.allocator.redeem_bootstrap(b'{not-json')
        if code != 400:
            fail('malformed json code', result)
            return
        record = json.loads(env.allocator.bootstrap_path(ticket.split('.')[1]).read_text())
        if record.get('bound_machine_id'):
            fail('malformed json bound ticket')
            return
        pass_('MALFORMED_JSON_NO_BIND')
    finally:
        env.cleanup()


def test_machine_id_rejected():
    env = Env()
    try:
        ticket, _e, _r = env.issue()
        for mid in ('../etc/passwd', 'a/b', 'x' * 200, 'has\nnewline'):
            body = json.dumps({
                'ticket': ticket,
                'machine_id': mid,
                'hostname': 'h',
            }).encode()
            code, result = env.allocator.redeem_bootstrap(body)
            if code != 400:
                fail('machine_id %r' % mid, '%s %s' % (code, result))
                return
        record = json.loads(env.allocator.bootstrap_path(ticket.split('.')[1]).read_text())
        if record.get('bound_machine_id'):
            fail('bad machine_id bound ticket')
            return
        pass_('MACHINE_ID_VALIDATION')
    finally:
        env.cleanup()


def test_compare_digest_present():
    text = (ROOT / 'server' / 'frp-port-allocator.py').read_text(encoding='utf-8')
    if 'hmac.compare_digest' not in text:
        fail('compare_digest missing')
        return
    if 'hash_bootstrap_secret' not in text:
        fail('hash helper missing')
        return
    pass_('CONSTANT_TIME_SECRET_CHECK')


def test_bind_race():
    env = Env()
    try:
        wins = {'a': 0, 'b': 0, 'other': 0}
        for _i in range(20):
            ticket, _e, _r = env.issue()

            def go(mid):
                return env.redeem(ticket, mid)

            with ThreadPoolExecutor(max_workers=2) as pool:
                futs = [pool.submit(go, 'machine-a'), pool.submit(go, 'machine-b')]
                results = [fut.result() for fut in as_completed(futs)]
            ok = [r for r in results if r[0] == 200]
            bad = [r for r in results if r[0] != 200]
            if len(ok) != 1 or len(bad) != 1:
                fail('bind race counts', results)
                return
            if bad[0][0] != 409 or bad[0][1].get('error_class') != 'BOOTSTRAP_TICKET_BOUND':
                fail('bind race reject', bad[0])
                return
            bound = json.loads(env.allocator.bootstrap_path(ticket.split('.')[1]).read_text())
            winner = bound.get('bound_machine_id')
            if winner in wins:
                wins[winner.split('-')[-1] if False else ('a' if winner == 'machine-a' else 'b' if winner == 'machine-b' else 'other')] += 1
            else:
                wins['other'] += 1
        pass_('BOOTSTRAP_TICKET_RACE_SAFE')
    finally:
        env.cleanup()


def test_create_race():
    env = Env()
    try:
        seen = set()
        lock = threading.Lock()

        def go():
            ticket, enroll, record = env.issue()
            with lock:
                seen.add((ticket, enroll['id'], record['id']))

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(go) for _ in range(16)]
            for fut in as_completed(futs):
                fut.result()
        if len(seen) != 16:
            fail('create race unique', len(seen))
            return
        files = list(env.allocator.bootstrap_dir.glob('*.json'))
        if len(files) != 16:
            fail('create race files', len(files))
            return
        for path in files:
            json.loads(path.read_text())
        pass_('TICKET_CREATION_RACE')
    finally:
        env.cleanup()


def test_cleanup_expired():
    env = Env()
    try:
        ticket, _e, _r = env.issue(ttl=1)
        path = env.allocator.bootstrap_path(ticket.split('.')[1])
        rec = json.loads(path.read_text())
        rec['expires_at'] = int(time.time()) - 5
        path.write_text(json.dumps(rec, indent=2) + '\n')
        env.allocator.cleanup_expired_bootstrap_tickets()
        path = env.allocator.bootstrap_path(ticket.split('.')[1])
        if not path.exists():
            fail('expired ticket metadata removed')
            return
        pass_('BOOTSTRAP_TICKET_EXPIRY_RETAINED')
    finally:
        env.cleanup()


def test_enroll_reuses_existing_and_note():
    env = Env()
    try:
        ticket, enroll, _r = env.issue(note='customer-01')
        code, result = env.redeem(ticket, 'machine-a')
        if code != 200:
            fail('redeem before enroll', result)
            return
        body = json.dumps({
            'machine_id': 'machine-a',
            'hostname': 'host-a',
            'services': env.ssh_services(),
        }, separators=(',', ':')).encode()
        ts = str(int(time.time()))
        sig = hmac.new(
            enroll['secret'].encode(),
            (ts + '\n' + body.decode()).encode(),
            hashlib.sha256,
        ).hexdigest()
        ecode, eresult = env.allocator.enroll(enroll['id'], ts, sig, body)
        if ecode != 200:
            fail('enroll after redeem', eresult)
            return
        state = env.allocator.load_registry()
        client = state['clients']['machine-a']
        if client.get('note') != 'customer-01':
            fail('note not copied', client)
            return
        port1 = client['services']['ssh']['remote_port']
        ecode2, eresult2 = env.allocator.enroll(enroll['id'], ts, sig, body)
        if ecode2 != 200:
            fail('enroll retry', eresult2)
            return
        state2 = env.allocator.load_registry()
        port2 = state2['clients']['machine-a']['services']['ssh']['remote_port']
        if port1 != port2:
            fail('duplicate port', '%s %s' % (port1, port2))
            return
        if len(state2['clients']) != 1:
            fail('duplicate client')
            return
        pass_('NORMAL_ENROLLMENT_REUSED')
        pass_('NO_DUPLICATE_PORT_ALLOCATION')
        pass_('LOST_RESPONSE_RETRY_SAFE')
    finally:
        env.cleanup()


def test_redeem_retry_before_and_after_enroll():
    env = Env()
    try:
        ticket, enroll, _r = env.issue()
        code, result = env.redeem(ticket, 'machine-a')
        if code != 200:
            fail('first redeem', result)
            return
        code2, result2 = env.redeem(ticket, 'machine-a')
        if code2 != 200:
            fail('same-machine retry before enroll', result2)
            return
        if result2.get('enrollment_code') != result.get('enrollment_code'):
            fail('retry enrollment changed before enroll')
            return
        pass_('REDEEM_RETRY_BEFORE_ENROLL=PASS')

        code_other, result_other = env.redeem(ticket, 'machine-b')
        if code_other != 409 or result_other.get('error_class') != 'BOOTSTRAP_TICKET_BOUND':
            fail('second machine before enroll', '%s %s' % (code_other, result_other))
            return
        pass_('SECOND_MACHINE_REJECTED=PASS')

        body = json.dumps({
            'machine_id': 'machine-a',
            'hostname': 'host-a',
            'services': env.ssh_services(),
        }, separators=(',', ':')).encode()
        ts = str(int(time.time()))
        sig = hmac.new(
            enroll['secret'].encode(),
            (ts + '\n' + body.decode()).encode(),
            hashlib.sha256,
        ).hexdigest()
        ecode, eresult = env.allocator.enroll(enroll['id'], ts, sig, body)
        if ecode != 200:
            fail('enroll for ticket completion', eresult)
            return
        path = env.allocator.bootstrap_path(ticket.split('.')[1])
        stored = json.loads(path.read_text())
        if not stored.get('completed_at'):
            fail('ticket not marked completed', stored)
            return

        code3, result3 = env.redeem(ticket, 'machine-a')
        if code3 != 409 or result3.get('error_class') != 'BOOTSTRAP_TICKET_USED':
            fail('post-success redeem', '%s %s' % (code3, result3))
            return
        pass_('REDEEM_AFTER_SUCCESS_REJECTED=PASS')
        pass_('BOOTSTRAP_TICKET_USED')
    finally:
        env.cleanup()


def test_bootstrap_completion_fail_closed():
    """Enrollment must not succeed if bootstrap ticket completion cannot persist."""
    env = Env()
    try:
        ticket, enroll, _r = env.issue()
        code, result = env.redeem(ticket, 'machine-fail')
        if code != 200:
            fail('redeem before fail-closed enroll', result)
            return

        original = env.allocator.save_bootstrap

        def boom(path, record):
            raise OSError('injected bootstrap save failure')

        env.allocator.save_bootstrap = boom
        body = json.dumps({
            'machine_id': 'machine-fail',
            'hostname': 'host-fail',
            'services': env.ssh_services(),
        }, separators=(',', ':')).encode()
        ts = str(int(time.time()))
        sig = hmac.new(
            enroll['secret'].encode(),
            (ts + '\n' + body.decode()).encode(),
            hashlib.sha256,
        ).hexdigest()
        ecode, eresult = env.allocator.enroll(enroll['id'], ts, sig, body)
        env.allocator.save_bootstrap = original
        if ecode == 200:
            fail('enroll succeeded despite bootstrap save failure', eresult)
            return
        if eresult.get('error_class') != 'SERVER_MUTATION_FAILED':
            fail('unexpected enroll error class', eresult)
            return

        state = env.allocator.load_registry()
        if 'machine-fail' in (state.get('clients') or {}):
            fail('client left behind after bootstrap completion failure')
            return

        # Ticket remains usable for retry; must not create duplicates on success.
        code2, _result2 = env.redeem(ticket, 'machine-fail')
        if code2 != 200:
            fail('ticket not reusable after failed enroll', code2)
            return
        env.allocator.save_bootstrap = original
        ts2 = str(int(time.time()))
        sig2 = hmac.new(
            enroll['secret'].encode(),
            (ts2 + '\n' + body.decode()).encode(),
            hashlib.sha256,
        ).hexdigest()
        ecode2, eresult2 = env.allocator.enroll(enroll['id'], ts2, sig2, body)
        if ecode2 != 200:
            fail('retry enroll after injected failure', eresult2)
            return
        state2 = env.allocator.load_registry()
        clients = state2.get('clients') or {}
        if list(clients.keys()).count('machine-fail') != 1 and 'machine-fail' not in clients:
            fail('missing client after retry')
            return
        if len([k for k in clients if k == 'machine-fail']) != 1:
            fail('duplicate client after retry')
            return
        pass_('BOOTSTRAP_COMPLETION_FAIL_CLOSED')
    finally:
        env.cleanup()


def _enroll_as(env, enroll, machine_id, services, hostname='host-a'):
    body = json.dumps({
        'machine_id': machine_id,
        'hostname': hostname,
        'services': services,
    }, separators=(',', ':')).encode()
    ts = str(int(time.time()))
    sig = hmac.new(
        enroll['secret'].encode(),
        (ts + '\n' + body.decode()).encode(),
        hashlib.sha256,
    ).hexdigest()
    return env.allocator.enroll(enroll['id'], ts, sig, body)


def test_enroll_enforces_ticket_scope():
    """F27: the Enrollment Code proves possession, not authority to widen scope."""
    env = Env()
    try:
        rdp = [{
            'id': 'rdp',
            'name': 'RDP',
            'protocol': 'tcp',
            'local_ip': '127.0.0.1',
            'local_port': 3389,
            'preset': 'custom',
        }]

        # Management-only ticket: no service may be added at /enroll.
        ticket, enroll, _r = env.issue(services=[])
        code, _res = env.redeem(ticket, 'machine-mgmt')
        if code != 200:
            fail('redeem management-only ticket', code)
            return
        code, result = _enroll_as(env, enroll, 'machine-mgmt', env.ssh_services())
        if code != 403 or result.get('error_class') != 'SERVICE_SCOPE_VIOLATION':
            fail('management-only ticket accepted ssh', '%s %s' % (code, result))
            return
        state = env.allocator.load_registry()
        if 'machine-mgmt' in (state.get('clients') or {}) or env.allocator.used_ports(state):
            fail('rejected scope violation still mutated registry', state)
            return
        pass_('SCOPE_MANAGEMENT_ONLY_REJECTS_SSH')

        # SSH-only ticket: a different service is out of scope.
        ticket, enroll, _r = env.issue()
        code, _res = env.redeem(ticket, 'machine-ssh')
        if code != 200:
            fail('redeem ssh ticket', code)
            return
        for label, attempt in (
            ('rdp', rdp),
            ('ssh+rdp', env.ssh_services() + rdp),
            ('ssh-port', env.ssh_services(port=2222)),
            ('ssh-user', env.ssh_services(user='root')),
            ('empty', []),
        ):
            code, result = _enroll_as(env, enroll, 'machine-ssh', attempt)
            if code != 403 or result.get('error_class') != 'SERVICE_SCOPE_VIOLATION':
                fail('out-of-scope %s accepted' % label, '%s %s' % (code, result))
                return
        pass_('SCOPE_SSH_TICKET_REJECTS_OTHER_SERVICES')

        # The exact authorized set enrolls, and an exact lost-response replay
        # (same machine, same request) still recovers the committed response.
        code, result = _enroll_as(env, enroll, 'machine-ssh', env.ssh_services())
        if code != 200:
            fail('authorized services rejected', '%s %s' % (code, result))
            return
        allocated = result.get('services')
        code, replay = _enroll_as(env, enroll, 'machine-ssh', env.ssh_services())
        if code != 200 or replay.get('services') != allocated:
            fail('exact replay rejected', '%s %s' % (code, replay))
            return
        pass_('SCOPE_EXACT_SERVICES_ENROLL')
        pass_('SCOPE_EXACT_REPLAY_SAFE')

        # A changed service on replay stays rejected by scope, not silently applied.
        code, result = _enroll_as(env, enroll, 'machine-ssh', rdp)
        if code != 403 or result.get('error_class') != 'SERVICE_SCOPE_VIOLATION':
            fail('changed replay accepted', '%s %s' % (code, result))
            return
        state = env.allocator.load_registry()
        services = state['clients']['machine-ssh']['services']
        if set(services) != {'ssh'}:
            fail('changed replay mutated services', services)
            return
        pass_('SCOPE_CHANGED_REPLAY_REJECTED')

        # Order differences within the authorized set are not a violation.
        ticket, enroll, _r = env.issue(
            services=MOD.normalize_services(env.ssh_services() + rdp)
        )
        code, _res = env.redeem(ticket, 'machine-multi')
        if code != 200:
            fail('redeem multi ticket', code)
            return
        code, result = _enroll_as(
            env, enroll, 'machine-multi', rdp + env.ssh_services(),
            hostname='host-multi',
        )
        if code != 200:
            fail('reordered authorized services rejected', '%s %s' % (code, result))
            return
        pass_('SCOPE_ORDER_INDEPENDENT')
    finally:
        env.cleanup()


def test_manual_enrollment_without_scope_unrestricted():
    """Enrollment records with no ticket scope keep the pre-F27 behavior."""
    env = Env()
    try:
        ticket, enroll, _r = env.issue(services=[])
        code, _res = env.redeem(ticket, 'machine-manual')
        if code != 200:
            fail('redeem for manual downgrade', code)
            return
        path = env.allocator.enrollment_path(enroll['id'])
        record = json.loads(path.read_text())
        record.pop('authorized_services', None)
        env.allocator.save_enrollment(path, record)
        code, result = _enroll_as(env, enroll, 'machine-manual', env.ssh_services())
        if code != 200:
            fail('manual enrollment rejected', '%s %s' % (code, result))
            return
        pass_('MANUAL_ENROLLMENT_UNSCOPED_ALLOWED')
    finally:
        env.cleanup()


def main():
    test_issue_hashed_and_entropy()
    test_redeem_bind_and_retry()
    test_expired_and_invalid()
    test_malformed_json_no_bind()
    test_machine_id_rejected()
    test_compare_digest_present()
    test_bind_race()
    test_create_race()
    test_cleanup_expired()
    test_enroll_reuses_existing_and_note()
    test_redeem_retry_before_and_after_enroll()
    test_bootstrap_completion_fail_closed()
    test_enroll_enforces_ticket_scope()
    test_manual_enrollment_without_scope_unrestricted()
    if FAILED:
        print('BOOTSTRAP_TICKET_TEST=FAIL')
        return 1
    print('BOOTSTRAP_TICKET_TEST=PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
