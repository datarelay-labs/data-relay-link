#!/usr/bin/env python3
"""Bootstrap ticket issue/redeem tests. Isolated fixtures only."""
import base64
import hashlib
import hmac
import json
import re
import shlex
import subprocess
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


def record_id(ticket):
    parsed = MOD.parse_bootstrap_ticket(ticket)
    if not parsed:
        raise AssertionError('unparsed ticket %r' % (ticket,))
    return parsed[0]


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
        # Keep capacity available for multi-issue unit tests.
        try:
            return self.allocator.issue_bootstrap_ticket(services, ttl, note)
        except MOD.ZeroTouchCapacityError:
            self._force_release_capacity()
            return self.allocator.issue_bootstrap_ticket(services, ttl, note)

    def _force_release_capacity(self):
        now_iso = MOD.utc_now_iso()
        for path in self.allocator.bootstrap_dir.glob('*.json'):
            try:
                rec = json.loads(path.read_text())
            except Exception:
                continue
            if rec.get('completed_at') or rec.get('revoked_at'):
                continue
            rec['revoked_at'] = now_iso
            path.write_text(json.dumps(rec, indent=2) + '\n')

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
        parsed = MOD.parse_bootstrap_ticket(ticket)
        if not parsed:
            fail('ticket format', ticket)
            return
        ticket_id, secret = parsed
        if len(secret) != 64:
            fail('ticket entropy', len(secret))
            return
        handle = str(record.get('_short_handle') or '')
        if not MOD.COMPACT_CREDENTIAL_RE.fullmatch(handle):
            fail('short handle format', handle)
            return
        try:
            raw_entropy = base64.urlsafe_b64decode(handle + '==')
        except Exception as exc:
            fail('short handle encoding', exc)
            return
        if len(raw_entropy) != 16:
            fail('short handle entropy', len(raw_entropy))
            return
        path = env.allocator.bootstrap_path(ticket_id)
        stored = json.loads(path.read_text())
        raw = json.dumps(stored)
        if ticket in raw or secret in raw or handle in raw or '_short_handle' in stored:
            fail('raw credential stored', raw)
            return
        if stored.get('id') != ticket_id:
            fail('ticket id mismatch')
            return
        if stored.get('secret_hash') != MOD.hash_bootstrap_secret(secret):
            fail('secret hash mismatch')
            return
        if stored.get('short_handle_hash') != MOD.hash_bootstrap_secret(handle):
            fail('short handle hash mismatch')
            return
        wrapped = stored.get('bt1_wrapped')
        if (
            not isinstance(wrapped, dict)
            or wrapped.get('v') != 2
            or not wrapped.get('salt')
            or len(str(wrapped.get('mac') or '')) != 64
        ):
            fail('missing authenticated bt1 wrap', wrapped)
            return
        recovered = MOD.unwrap_bootstrap_ticket(wrapped, env.token.read_text().strip())
        if recovered != ticket or not MOD.bootstrap_wrap_matches_record(recovered, stored):
            fail('bt1 wrap did not recover')
            return
        if MOD.count_active_unused_bootstrap_tickets(env.allocator.bootstrap_dir) != 1:
            fail('handle index changed active ticket count')
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
        bound = json.loads(env.allocator.bootstrap_path(record_id(ticket)).read_text())
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
        path = env.allocator.bootstrap_path(record_id(ticket))
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
            'bt1.' + record_id(good) + '.' + ('0' * 64),
            'x' * 200,
            '',
            'A' * 21,
            'A' * 23,
            'A' * 21 + '=',
            'abcd+efghijklmnopqr',
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
        record = json.loads(env.allocator.bootstrap_path(record_id(ticket)).read_text())
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
        record = json.loads(env.allocator.bootstrap_path(record_id(ticket)).read_text())
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
            bound = json.loads(env.allocator.bootstrap_path(record_id(ticket)).read_text())
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
            futs = [pool.submit(go) for _ in range(10)]
            for fut in as_completed(futs):
                fut.result()
        if len(seen) != 10:
            fail('create race unique', len(seen))
            return
        files = list(env.allocator.bootstrap_dir.glob('*.json'))
        if len(files) != 10:
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
        path = env.allocator.bootstrap_path(record_id(ticket))
        rec = json.loads(path.read_text())
        rec['expires_at'] = int(time.time()) - 5
        path.write_text(json.dumps(rec, indent=2) + '\n')
        env.allocator.cleanup_expired_bootstrap_tickets()
        path = env.allocator.bootstrap_path(record_id(ticket))
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
        path = env.allocator.bootstrap_path(record_id(ticket))
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


def test_legacy_bt1_still_redeems():
    env = Env()
    try:
        ticket_id = 'abcdef0123456789'
        secret = 'ab' * 32
        raw = 'bt1.%s.%s' % (ticket_id, secret)
        enrollment_id = '0123456789abcdef'
        now = int(time.time())
        enroll = {
            'id': enrollment_id,
            'secret': 'cd' * 32,
            'created_at': MOD.utc_now_iso(),
            'expires_at': now + 600,
            'bound_machine_id': None,
            'used_at': None,
            'note': 'legacy',
            'label': '',
            'authorized_services': env.ssh_services(),
        }
        record = {
            'schema': 1,
            'id': ticket_id,
            'secret_hash': MOD.hash_bootstrap_secret(secret),
            'enrollment_id': enrollment_id,
            'created_at': MOD.utc_now_iso(),
            'expires_at': now + 600,
            'bound_machine_id': None,
            'completed_at': None,
            'note': 'legacy',
            'label': '',
            'services': env.ssh_services(),
            'use_count_max': 1,
        }
        env.allocator.save_enrollment(env.allocator.enrollment_path(enrollment_id), enroll)
        env.allocator.save_bootstrap(env.allocator.bootstrap_path(ticket_id), record)
        if not env.allocator.short_url_bootstrap_available(raw):
            fail('legacy short url unavailable')
            return
        code, result = env.redeem(raw, 'machine-legacy')
        if code != 200 or 'enrollment_code' not in result:
            fail('legacy redeem', '%s %s' % (code, result))
            return
        pass_('LEGACY_BT1_STILL_REDEEMS')
    finally:
        env.cleanup()


def test_compact_collision_does_not_overwrite():
    env = Env()
    original = MOD.generate_compact_bootstrap_credential
    forced = 'A' * 22
    calls = {'n': 0}

    def generator():
        calls['n'] += 1
        if calls['n'] == 1:
            return forced
        return original()

    MOD.generate_compact_bootstrap_credential = generator
    try:
        occupied = MOD.compact_bootstrap_record_id(forced)
        path = MOD.short_handle_index_path(env.allocator.bootstrap_dir, occupied)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"ticket_id":"%s","handle_hash":"%s","keep":true}\n' % (
            occupied, MOD.hash_bootstrap_secret(forced),
        ))
        before = path.read_text()
        ticket, _enroll, record = env.issue()
        handle = str(record.get('_short_handle') or '')
        if handle == forced or ticket == forced:
            fail('collision reused forced credential', handle)
            return
        if path.read_text() != before:
            fail('collision overwrote existing handle index')
            return
        if not path.exists() or not env.allocator.bootstrap_path(record['id']).is_file():
            fail('collision missing new ticket file')
            return
        pass_('COMPACT_ID_COLLISION_DOES_NOT_OVERWRITE')
    finally:
        MOD.generate_compact_bootstrap_credential = original
        env.cleanup()


def test_get_does_not_consume_compact():
    env = Env()
    try:
        ticket, _enroll, record = env.issue()
        handle = str(record.get('_short_handle') or '')
        path = env.allocator.bootstrap_path(record['id'])
        before = path.read_text()
        if not env.allocator.short_url_bootstrap_available(ticket):
            fail('bt1 get unavailable')
            return
        if not env.allocator.short_url_bootstrap_available(handle):
            fail('compact get unavailable')
            return
        after = json.loads(path.read_text())
        if path.read_text() != before:
            fail('get mutated ticket')
            return
        if after.get('bound_machine_id') or after.get('completed_at'):
            fail('get bound or consumed ticket', after)
            return
        if env.allocator.short_url_bootstrap_available('B' * 22):
            fail('unknown compact accepted')
            return
        code, result = env.redeem('B' * 22)
        if code != 403:
            fail('unknown compact redeem', '%s %s' % (code, result))
            return
        code_bt1, _result_bt1 = env.redeem(ticket, 'machine-handle')
        if code_bt1 != 200:
            fail('bt1 redeem after handle get', code_bt1)
            return
        mismatch = 'C' * 22
        mismatch_id = MOD.compact_bootstrap_record_id(mismatch)
        index = MOD.short_handle_index_path(env.allocator.bootstrap_dir, mismatch_id)
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(json.dumps({
            'ticket_id': record['id'],
            'handle_hash': '0' * 64,
        }) + '\n')
        if env.allocator.short_url_bootstrap_available(mismatch):
            fail('verifier mismatch accepted')
            return
        pass_('COMPACT_GET_DOES_NOT_CONSUME')
        pass_('COMPACT_UNKNOWN_AND_MISMATCH_FAIL_CLOSED')
    finally:
        env.cleanup()


def test_compact_redaction_and_command_length():
    spec = importlib.util.spec_from_file_location('frp_zero_touch', ROOT / 'lib' / 'frp_zero_touch.py')
    zt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(zt)
    doctor_spec = importlib.util.spec_from_file_location('frp_doctor', ROOT / 'lib' / 'frp_doctor.py')
    doctor = importlib.util.module_from_spec(doctor_spec)
    doctor_spec.loader.exec_module(doctor)
    audit_spec = importlib.util.spec_from_file_location('frp_audit', ROOT / 'lib' / 'frp_audit.py')
    audit = importlib.util.module_from_spec(audit_spec)
    audit_spec.loader.exec_module(audit)
    compact = 'AbcdEFghij1234_-KLMNOP'
    if len(compact) != 22:
        fail('fixture length', len(compact))
        return
    url = zt.short_url_for_ticket('remote.xdr.ooo', compact)
    cmd = zt.short_url_command('remote.xdr.ooo', compact)
    if len(url) != 47 or cmd != 'curl -fsSL %s|sudo bash' % url:
        fail('compact command shape', '%s %s' % (len(url), cmd))
        return
    if len(cmd) != 68:
        fail('compact command length', len(cmd))
        return
    quoted = zt.short_url_command('bad host.example', compact)
    if compact not in quoted or not quoted.startswith("curl -fsSL '"):
        fail('unsafe host not quoted', quoted)
        return
    sb_spec = importlib.util.spec_from_file_location(
        'frp_support_bundle', ROOT / 'lib' / 'frp_support_bundle.py'
    )
    support = importlib.util.module_from_spec(sb_spec)
    sb_spec.loader.exec_module(support)
    win_script = zt.render_short_url_windows_bootstrap_script(
        'https://203.0.113.10/enroll',
        'ab' * 32,
        compact,
        'https://example.test/artifacts/agent/bootstrap-client.ps1',
    )
    samples = [
        doctor.redact('FRP_BOOTSTRAP_TICKET=%s' % compact),
        doctor.redact("FRP_BOOTSTRAP_TICKET='%s'" % compact),
        doctor.redact('$env:FRP_BOOTSTRAP_TICKET = \'%s\'' % compact),
        doctor.redact('GET /i/%s HTTP/1.1' % compact),
        zt.redact_text('FRP_BOOTSTRAP_TICKET=%s' % compact),
        zt.redact_text('$env:FRP_BOOTSTRAP_TICKET = \'%s\'' % compact),
        zt.redact_text('https://remote.xdr.ooo/i/%s' % compact),
        zt.redact_text(win_script),
        support.redact_text('FRP_BOOTSTRAP_TICKET=%s' % compact),
        support.redact_text('GET /i/%s HTTP/1.1' % compact),
        json.dumps(support.sanitize_json_value({
            'bootstrap_ticket': compact,
            'message': 'GET /i/%s done' % compact,
            'label': 'web01',
        })),
        json.dumps(audit._redact({'ticket': compact, 'bootstrap': compact, 'note': 'ok'})),
        json.dumps(audit._redact({'message': 'GET /i/%s done' % compact})),
        json.dumps(audit._redact({'message': 'FRP_BOOTSTRAP_TICKET=%s' % compact})),
        json.dumps(audit._redact({'message': "$env:FRP_BOOTSTRAP_TICKET = '%s'" % compact})),
    ]
    for sample in samples:
        if compact in sample:
            fail('compact leaked', sample)
            return
    plain = audit._redact({'note': 'status ok', 'label': 'web01'})
    if plain.get('note') != 'status ok' or plain.get('label') != 'web01':
        fail('non-secret field rewritten', plain)
        return
    issue_env = Env()
    try:
        ticket, _enroll, record = issue_env.issue(note='customer-note')
        stored = json.loads(issue_env.allocator.bootstrap_path(record['id']).read_text())
        handle = str(record.get('_short_handle') or '')
        if handle and handle in json.dumps(stored):
            fail('raw short handle persisted')
            return
        if ticket in json.dumps(stored):
            fail('raw bt1 persisted')
            return
    finally:
        issue_env.cleanup()
    emitted = {
        'label': record.get('label'),
        'note': record.get('note'),
        'ticket_id': record.get('id'),
        'message': 'enrollment created',
    }
    if ticket in json.dumps(record) or ticket in json.dumps(emitted):
        fail('naked credential emitted in non-secret record', emitted)
        return
    redacted = audit._redact(emitted)
    if ticket in json.dumps(redacted):
        fail('naked credential survived audit redact', redacted)
        return
    if redacted.get('note') != 'customer-note' or redacted.get('message') != 'enrollment created':
        fail('generic message rewritten', redacted)
        return
    if redacted.get('ticket_id') != '[REDACTED]':
        fail('ticket key not redacted', redacted)
        return
    pass_('COMPACT_REDACTION_AND_COMMAND_LENGTH')


def _pipeline_tokens(command):
    # Python 3.7 shlex absorbs '|' into the current word when
    # whitespace_split is set, so 'url|sudo' is one token. Later Pythons
    # keep the pipe. Leave whitespace_split off and treat ':' as a word
    # character so an unquoted https URL stays one token and the pipe
    # stays a separate boundary on both.
    lexer = shlex.shlex(command, posix=True, punctuation_chars='|')
    lexer.wordchars += ':'
    return list(lexer)


def test_shell_safety_floor():
    alphabet = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')
    unsafe = set(" \t\n;|&$`'\"\\<>()*?[]{}~!")
    for _ in range(10000):
        token = MOD.generate_compact_bootstrap_credential()
        if len(token) != 22 or (set(token) - alphabet):
            fail('credential alphabet', token)
            return
        if len(base64.urlsafe_b64decode(token + '==')) != 16:
            fail('credential entropy bytes', token)
            return
    spec = importlib.util.spec_from_file_location('frp_zero_touch', ROOT / 'lib' / 'frp_zero_touch.py')
    zt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(zt)
    compact = 'A' * 22
    cmd = zt.short_url_command('remote.xdr.ooo', compact)
    url = 'https://remote.xdr.ooo/i/%s' % compact
    if cmd != 'curl -fsSL %s|sudo bash' % url or len(cmd) != 68:
        fail('68-char target', '%s %s' % (len(cmd), cmd))
        return
    if not cmd.startswith('curl -fsSL https://') or '/i/' not in cmd or not cmd.endswith('|sudo bash'):
        fail('safety model flags removed', cmd)
        return
    if set(url) & unsafe:
        fail('url metacharacter', url)
        return
    tokens = _pipeline_tokens(cmd)
    if tokens != ['curl', '-fsSL', url, '|', 'sudo', 'bash']:
        fail('shell tokens', tokens)
        return
    sample = MOD.generate_compact_bootstrap_credential()
    sample_cmd = zt.short_url_command('remote.xdr.ooo', sample)
    sample_url = 'https://remote.xdr.ooo/i/%s' % sample
    if _pipeline_tokens(sample_cmd) != ['curl', '-fsSL', sample_url, '|', 'sudo', 'bash']:
        fail('random credential tokens', sample_cmd)
        return
    quoted = zt.short_url_command('bad host.example', compact)
    quoted_tokens = _pipeline_tokens(quoted)
    if '|' not in quoted_tokens or any('bad' in part and 'host' in part and ' ' not in part for part in quoted_tokens):
        fail('unsafe host split', quoted_tokens)
        return
    if not any('bad host.example' in part for part in quoted_tokens):
        fail('unsafe host not kept as one word', quoted_tokens)
        return
    proc = subprocess.run(
        ['bash', '-c', 'set -f; left=${1%%|*}; right=${1#*|}; set -- $left; printf "%s\\n" "$#" "$@"; set -- $right; printf "%s\\n" "$#" "$@"', 'bash', cmd],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        fail('bash tokenize', proc.stderr)
        return
    lines = proc.stdout.splitlines()
    if lines != ['3', 'curl', '-fsSL', url, '2', 'sudo', 'bash']:
        fail('bash pipeline split', lines)
        return
    pass_('SHELL_SAFETY_68_CHAR_FLOOR')


def test_windows_renderer_frozen_and_launcher():
    env = Env()
    inputs = {
        'allocator_url': 'https://remote.xdr.ooo/enroll',
        'allocator_ca_sha256': 'ab' * 32,
        'installer_url': 'https://remote.xdr.ooo/bootstrap-client.ps1',
    }
    original = MOD.windows_renderer_inputs_from_cfg
    MOD.windows_renderer_inputs_from_cfg = lambda cfg: dict(inputs)
    try:
        ticket, _enroll, record = env.issue()
        handle = str(record.get('_short_handle') or '')
        path = env.allocator.bootstrap_path(record['id'])
        stored = json.loads(path.read_text())
        renderer = stored.get('windows_renderer') or {}
        if renderer.get('version') != 1:
            fail('renderer version', renderer)
            return
        if handle in json.dumps(stored) or ticket in json.dumps(stored):
            fail('raw credential in frozen record')
            return
        script = env.allocator.build_short_url_script(handle, 'windows')
        if not script:
            fail('frozen stage1 missing')
            return
        digest = hashlib.sha256(script.encode('utf-8')).hexdigest()
        if digest != renderer.get('stage1_sha256'):
            fail('stage1 digest mismatch', digest)
            return
        env.allocator.cfg['allocator_public_url'] = 'https://evil.example/enroll'
        env.allocator.cfg['windows_client_installer_url'] = 'https://evil.example/x.ps1'
        again = env.allocator.build_short_url_script(handle, 'windows')
        if again != script:
            fail('config mutation changed stage1')
            return
        stored['windows_renderer']['version'] = 99
        path.write_text(json.dumps(stored, indent=2) + '\n')
        if env.allocator.build_short_url_script(handle, 'windows') is not None:
            fail('unknown renderer version served a script')
            return
        zt_spec = importlib.util.spec_from_file_location(
            'frp_zero_touch_launcher', ROOT / 'lib' / 'frp_zero_touch.py'
        )
        zt = importlib.util.module_from_spec(zt_spec)
        zt_spec.loader.exec_module(zt)
        command = zt.windows_strict_launcher('remote.xdr.ooo', 'A' * 22, digest)
        if len(command) != 420:
            fail('windows launcher length', len(command))
            return
        if 'curl.exe' not in command or 'Get-FileHash' not in command:
            fail('launcher missing curl or hash', command)
            return
        if 'powershell.exe -Command' in command or 'Invoke-Expression' in command:
            fail('launcher uses outer command or iex', command)
            return
        if re.search(r'(^|[^A-Za-z0-9])(irm|iex)([^A-Za-z0-9]|$)', command):
            fail('launcher uses irm or iex', command)
            return
        if handle in script or ticket not in script:
            fail('windows stage1 credential', 'handle leaked' if handle in script else 'bt1 missing')
            return
        ca = env.root / 'ca.crt'
        ca.write_text('not-a-cert\n')
        env.allocator.cfg['tls_ca_cert'] = str(ca)
        env.allocator.cfg['allocator_public_url'] = inputs['allocator_url']
        env.allocator.cfg['client_installer_url'] = 'https://remote.xdr.ooo/bootstrap-client.sh'
        original_fp = MOD.PKI.fingerprint_from_cert_file
        MOD.PKI.fingerprint_from_cert_file = lambda path: 'cd' * 32
        try:
            linux = env.allocator.build_short_url_script(handle, 'linux')
        finally:
            MOD.PKI.fingerprint_from_cert_file = original_fp
        package = re.search(r'zt1\.[A-Za-z0-9_-]+', linux or '')
        if not package:
            fail('linux stage1 missing zt1')
            return
        encoded = package.group(0).split('.', 1)[1]
        encoded += '=' * ((4 - len(encoded) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode('ascii')).decode('utf-8'))
        if payload.get('t') != ticket:
            fail('linux stage1 credential', payload.get('t'))
            return
        code, result = env.redeem(handle, 'machine-win')
        if code != 403:
            fail('handle redeem must reject', '%s %s' % (code, result))
            return
        code_bt1, result_bt1 = env.redeem(ticket, 'machine-win')
        if code_bt1 != 200:
            fail('internal bt1 redeem', '%s %s' % (code_bt1, result_bt1))
            return
        code2, result2 = env.redeem(ticket, 'machine-other')
        if code2 != 409:
            fail('bt1 second machine', '%s %s' % (code2, result2))
            return
        stored['bt1_wrapped']['ct'] = 'AAAA'
        path.write_text(json.dumps(stored, indent=2) + '\n')
        if env.allocator.build_short_url_script(handle, 'windows') is not None:
            fail('corrupt wrap served a script')
            return
        if env.allocator.build_short_url_script(handle, 'linux') is not None:
            fail('corrupt wrap served linux stage1')
            return
        pass_('WINDOWS_RENDERER_FROZEN_420')
    finally:
        MOD.windows_renderer_inputs_from_cfg = original
        env.cleanup()


def test_handle_index_removed_with_retention():
    env = Env()
    try:
        _ticket, enroll, record = env.issue()
        handle = str(record.get('_short_handle') or '')
        index = MOD.short_handle_index_path(
            env.allocator.bootstrap_dir,
            MOD.hash_bootstrap_secret(handle)[:16],
        )
        if index is None or not index.is_file():
            fail('handle index missing before purge')
            return
        if MOD.count_active_unused_bootstrap_tickets(env.allocator.bootstrap_dir) != 1:
            fail('handle index double-counted')
            return
        revoked_at = int(time.time()) - (3 * 86400)
        for path in (
            env.allocator.bootstrap_path(record['id']),
            env.allocator.enrollment_path(enroll['id']),
        ):
            rec = json.loads(path.read_text())
            rec['revoked_at'] = revoked_at
            path.write_text(json.dumps(rec) + '\n')
        elc_spec = importlib.util.spec_from_file_location(
            'frp_enrollment_lifecycle', ROOT / 'lib' / 'frp_enrollment_lifecycle.py'
        )
        elc = importlib.util.module_from_spec(elc_spec)
        elc_spec.loader.exec_module(elc)
        elc.run_retention_cleanup_locked(
            env.allocator.enrollments_dir,
            env.allocator.bootstrap_dir,
            env.allocator.registry_file,
            1,
            now=int(time.time()),
        )
        if index.exists() or env.allocator.bootstrap_path(record['id']).exists():
            fail('retention left ticket or handle index')
            return
        if env.allocator.enrollment_path(enroll['id']).exists():
            fail('retention left enrollment')
            return
        pass_('HANDLE_INDEX_RETENTION_PURGE')
    finally:
        env.cleanup()


def test_wrap_without_optional_cryptography():
    """Issue and recover bt1 when the optional ACME cryptography package is absent."""
    import builtins
    real_import = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        if str(name).split('.', 1)[0] == 'cryptography':
            raise ImportError('simulated optional cryptography unavailable')
        return real_import(name, globals, locals, fromlist, level)

    env = Env()
    try:
        builtins.__import__ = guarded
        ticket, _enroll, _record = env.issue()
        stored = json.loads(env.allocator.bootstrap_path(record_id(ticket)).read_text())
        recovered = MOD.unwrap_bootstrap_ticket(
            stored.get('bt1_wrapped'), env.token.read_text().strip()
        )
        if recovered != ticket:
            fail('openssl wrap without cryptography', recovered)
            return
        key_dir = env.root / 'notoken-bootstrap'
        key_dir.mkdir()
        secret = MOD.bootstrap_wrap_secret({}, key_dir, create=True)
        key_path = key_dir / MOD.BOOTSTRAP_WRAP_KEY_NAME
        if (
            not secret
            or not key_path.is_file()
            or key_path.name.startswith('.')
            or key_path not in key_dir.rglob('*')
        ):
            fail('wrap key missing from backup glob', key_path)
            return
        if oct(key_path.stat().st_mode & 0o777) != '0o600':
            fail('wrap key mode', oct(key_path.stat().st_mode & 0o777))
            return
        blob = MOD.wrap_bootstrap_ticket(ticket, secret)
        if MOD.unwrap_bootstrap_ticket(blob, secret) != ticket:
            fail('dedicated wrap key roundtrip')
            return
        if MOD.unwrap_bootstrap_ticket(blob, 'wrong-secret') is not None:
            fail('wrong wrap secret accepted')
            return
        tampered = dict(blob)
        tampered['mac'] = '0' * 64
        if MOD.unwrap_bootstrap_ticket(tampered, secret) is not None:
            fail('tampered wrap mac accepted')
            return
        tampered = dict(blob)
        tampered['ct'] = 'AAAA'
        if MOD.unwrap_bootstrap_ticket(tampered, secret) is not None:
            fail('tampered wrap ciphertext accepted')
            return
        bundle_spec = importlib.util.spec_from_file_location(
            'frp_support_bundle', ROOT / 'lib' / 'frp_support_bundle.py'
        )
        bundle = importlib.util.module_from_spec(bundle_spec)
        bundle_spec.loader.exec_module(bundle)
        if not bundle.is_forbidden_source(key_path):
            fail('support bundle would copy wrap key', key_path.name)
            return
        pass_('OPENSSL_WRAP_WITHOUT_CRYPTOGRAPHY')
    finally:
        builtins.__import__ = real_import
        env.cleanup()


def main():
    test_issue_hashed_and_entropy()
    test_wrap_without_optional_cryptography()
    test_legacy_bt1_still_redeems()
    test_compact_collision_does_not_overwrite()
    test_get_does_not_consume_compact()
    test_compact_redaction_and_command_length()
    test_shell_safety_floor()
    test_windows_renderer_frozen_and_launcher()
    test_handle_index_removed_with_retention()
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
