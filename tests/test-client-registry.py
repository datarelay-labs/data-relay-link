#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import frp_client_registry as creg  # noqa: E402


def pass_(name):
    print('PASS %s' % name)


def fail(name, detail=''):
    print('FAIL %s %s' % (name, detail), file=sys.stderr)
    raise SystemExit(1)


def test_source_ip():
    if creg.request_source_ip('203.0.113.10', {'X-Forwarded-For': '1.2.3.4'}) != '203.0.113.10':
        fail('direct ignores XFF')
    if creg.request_source_ip('127.0.0.1', {'X-Forwarded-For': '198.51.100.9'}) != '198.51.100.9':
        fail('loopback trusts XFF')
    if creg.request_source_ip('::1', {'X-Forwarded-For': '2001:db8::1'}) != '2001:db8::1':
        fail('v6 loopback trusts XFF')
    if creg.request_source_ip('127.0.0.1', {'X-Forwarded-For': 'not-an-ip'}) != '127.0.0.1':
        fail('malformed XFF ignored')
    if creg.request_source_ip('::ffff:127.0.0.1', {'X-Forwarded-For': '203.0.113.8'}) != '203.0.113.8':
        fail('mapped loopback')
    pass_('SOURCE_IP_TRUST_BOUNDARY')


def test_display_and_match():
    state = {
        'schema_version': 2,
        'clients': {
            'aabbccdd00112233': {
                'hostname': 'ubuntu',
                'label': 'seoul-web01',
                'note': 'office',
            },
            'ddeeff0011223344': {
                'hostname': 'ubuntu',
                'label': 'busan-backup',
            },
            '0303cedf99999999': {
                'hostname': 'aella',
            },
        },
    }
    if creg.display_name(state['clients']['0303cedf99999999'], '0303cedf99999999') != 'aella':
        fail('fallback hostname')
    mid, client = creg.resolve_client(state, 'seoul-web01')
    if mid != 'aabbccdd00112233':
        fail('label lookup', mid)
    try:
        creg.resolve_client(state, 'ubuntu')
        fail('duplicate hostname should be ambiguous')
    except creg.ClientLookupError as exc:
        if len(exc.matches) != 2:
            fail('ambiguous candidates', exc.matches)
    mid, client = creg.resolve_client(state, '0303cedf')
    if mid != '0303cedf99999999':
        fail('prefix lookup', mid)
    mid, client = creg.resolve_client(state, 'SEOUL-WEB01')
    if mid != 'aabbccdd00112233':
        fail('case-insensitive label shortcut', mid)
    mid, client = creg.resolve_client(state, 'AELLA')
    if mid != '0303cedf99999999':
        fail('case-insensitive hostname shortcut', mid)
    try:
        creg.resolve_client(state, 'UBUNTU')
        fail('case-insensitive duplicate hostname should be ambiguous')
    except creg.ClientLookupError as exc:
        if len(exc.matches) != 2:
            fail('case-insensitive ambiguous hostname', exc.matches)
    if creg.find_client_id_by_label(state, 'Seoul-Web01') != 'aabbccdd00112233':
        fail('find_client_id_by_label case fold')
    groups = {
        'schema_version': 2,
        'clients': {},
        'groups': {
            'grp_aaaaaaaa': {'name': 'Edge-Sites'},
            'grp_bbbbbbbb': {'name': 'other'},
        },
    }
    if creg.find_group_id_by_name(groups, 'edge-sites') != 'grp_aaaaaaaa':
        fail('group name case-insensitive uniqueness')
    gid, group = creg.resolve_group(groups, 'EDGE-SITES')
    if gid != 'grp_aaaaaaaa':
        fail('group resolve case-insensitive', gid)
    pass_('CASE_INSENSITIVE_SHORTCUTS')
    # CLIENT ID / prefix must win over label or hostname collisions.
    collision = {
        'schema_version': 2,
        'clients': {
            'abcdef1200112233': {
                'hostname': 'host-a',
                'label': 'other-label',
            },
            'ffffffffffff0001': {
                'hostname': 'host-b',
                'label': 'abcdef12',
            },
        },
    }
    mid, client = creg.resolve_client(collision, 'abcdef12')
    if mid != 'abcdef1200112233':
        fail('CLIENT ID prefix must win over label', mid)
    host_collision = {
        'schema_version': 2,
        'clients': {
            '1122334455667788': {
                'hostname': 'edge-01',
                'label': 'label-a',
            },
            '99aabbccddeeff00': {
                'hostname': '11223344',
                'label': 'label-b',
            },
        },
    }
    mid, client = creg.resolve_client(host_collision, '11223344')
    if mid != '1122334455667788':
        fail('CLIENT ID prefix must win over hostname', mid)
    ids = ['abcdabcd11112222', 'abcdabcd99998888', '24cd7856aabbccdd']
    if creg.unique_short_id('24cd7856aabbccdd', ids) != '24cd7856':
        fail('unique short id')
    if creg.unique_short_id('abcdabcd11112222', ids) != 'abcdabcd1':
        fail('longer unique prefix', creg.unique_short_id('abcdabcd11112222', ids))
    amb = {
        'schema_version': 2,
        'clients': {
            'abcdabcd11112222': {'hostname': 'amb-one'},
            'abcdabcd99998888': {'hostname': 'amb-two'},
        },
    }
    try:
        creg.resolve_client(amb, 'abcdabcd')
        fail('ambiguous prefix should fail closed')
    except creg.ClientLookupError as exc:
        if len(exc.matches) != 2:
            fail('ambiguous prefix candidates', exc.matches)
    pass_('LABEL_HOSTNAME_PREFIX_LOOKUP')
    pass_('CLIENT_ID_UNIQUE_SHORT')


def test_seed_does_not_overwrite():
    client = {
        'label': 'keep-me',
        'note': 'keep-note',
        'tags': {'customer': 'lotte', 'site': 'seoul'},
    }
    creg.seed_admin_metadata(client, label='new', note='new-note')
    if client['label'] != 'keep-me' or client['note'] != 'keep-note':
        fail('overwrite', client)
    if client['tags'] != {'customer': 'lotte', 'site': 'seoul'}:
        fail('tags overwritten', client)
    empty = {}
    creg.seed_admin_metadata(empty, label='seoul-groupware', note='desc')
    if empty.get('label') != 'seoul-groupware':
        fail('seed label')
    pass_('SEED_ADMIN_METADATA')


def test_tags():
    if creg.parse_tag_assignment('customer=lotte') != ('customer', 'lotte'):
        fail('parse tag assignment')
    filters = [('customer', 'lotte'), ('site', 'seoul')]
    if not creg.client_matches_tags(
        {'tags': {'customer': 'lotte', 'site': 'seoul', 'role': 'dp'}},
        filters,
    ):
        fail('tag AND match')
    if creg.client_matches_tags({'tags': {'customer': 'lotte'}}, filters):
        fail('tag AND missing key')
    invalid = [
        'missing-equals',
        '=value',
        'bad key=value',
        'key=',
        'key=bad,value',
        'key=bad\x1bvalue',
        'key=bad\x00value',
        'key=bad\rvalue',
        'key=bad\nvalue',
        ('k' * 65) + '=value',
        'key=' + ('v' * 129),
    ]
    for value in invalid:
        try:
            creg.parse_tag_assignment(value)
            fail('invalid tag accepted', repr(value))
        except ValueError:
            pass
    pass_('CLIENT_TAG_VALIDATION_AND_MATCHING')


def main():
    test_source_ip()
    test_display_and_match()
    test_seed_does_not_overwrite()
    test_tags()
    print('CLIENT_REGISTRY_HELPERS=PASS')


if __name__ == '__main__':
    main()
