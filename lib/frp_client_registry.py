#!/usr/bin/env python3
"""Client registry identity helpers.

Immutable identity is machine_id. Hostname is observed from the client.
label/note/tags/group_ids are server-owned and must survive re-enrollment.
"""
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

LABEL_MAX_LEN = 64
NOTE_MAX_LEN = 1024
HOSTNAME_MAX_LEN = 253
TAG_KEY_MAX_LEN = 64
TAG_VALUE_MAX_LEN = 128
SHORT_MACHINE_ID_LEN = 8
GROUP_NAME_MAX_LEN = 64
GROUP_DESCRIPTION_MAX_LEN = 1024
GROUP_ID_PREFIX = 'grp_'
GROUP_ID_HEX_LEN = 8
RESERVED_GROUP_NAMES = frozenset({'all', 'ungrouped'})
SYSTEM_GROUP_ALL = 'all'
SYSTEM_GROUP_UNGROUPED = 'ungrouped'
LABEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$')
TAG_KEY_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
TAG_VALUE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@+ -]{0,127}$')
GROUP_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
GROUP_ID_RE = re.compile(r'^grp_[0-9a-f]{8}$')


class ClientLookupError(Exception):
    def __init__(self, message, matches=None):
        super().__init__(message)
        self.matches = list(matches or [])


class GroupLookupError(Exception):
    def __init__(self, message, matches=None):
        super().__init__(message)
        self.matches = list(matches or [])


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def header_get(headers, name):
    if headers is None:
        return ''
    getter = getattr(headers, 'get', None)
    if getter is None:
        return ''
    value = getter(name)
    if value is None:
        try:
            value = getter(name.lower())
        except Exception:
            value = None
    if value is None:
        return ''
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ''
    return str(value).strip()


def normalize_ip(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith('[') and ']' in text:
        text = text[1:text.index(']')]
    if '%' in text:
        text = text.split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def is_loopback_ip(value):
    parsed = normalize_ip(value)
    if parsed is None:
        return False
    return ipaddress.ip_address(parsed).is_loopback


def first_forwarded_ip(value):
    if value is None:
        return None
    for part in str(value).split(','):
        parsed = normalize_ip(part)
        if parsed is not None:
            return parsed
    return None


def request_source_ip(peer_host, headers=None):
    """Return the observed request source IP.

    Trust X-Forwarded-For only when the TCP peer is loopback (nginx on
    single443). Otherwise use the socket peer. Never use source IP as
    identity.
    """
    peer = normalize_ip(peer_host)
    if peer is not None and is_loopback_ip(peer):
        forwarded = first_forwarded_ip(header_get(headers, 'X-Forwarded-For'))
        if forwarded is None:
            forwarded = first_forwarded_ip(header_get(headers, 'X-Real-IP'))
        if forwarded is not None:
            return forwarded
    return peer


def sanitize_display(value, max_len=None):
    text = '' if value is None else str(value)
    cleaned = []
    for ch in text:
        if ord(ch) < 32 or 127 <= ord(ch) <= 159:
            cleaned.append(' ')
        else:
            cleaned.append(ch)
    out = ''.join(cleaned).strip()
    if max_len is not None and len(out) > int(max_len):
        out = out[: int(max_len)]
    return out


def validate_text_field(value, field, max_len, required=False):
    """Validate stored/displayed text while preserving normal Unicode."""
    text = '' if value is None else str(value).strip()
    if not text:
        if required:
            raise ValueError('%s is required' % field)
        return ''
    if len(text) > int(max_len):
        raise ValueError('%s must be at most %s characters' % (field, max_len))
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in text):
        raise ValueError('%s must not contain control characters' % field)
    return text


def validate_hostname(value, required=False):
    return validate_text_field(value, 'hostname', HOSTNAME_MAX_LEN, required=required)


def ssh_user_display(service):
    user = sanitize_display((service or {}).get('ssh_user') or '', 32)
    return user if user else 'legacy / unspecified'


def passive_listening_ports():
    """Return (ports, known) from ss without connecting to any socket."""
    binary = shutil.which('ss')
    if not binary:
        return set(), False
    for args in ([binary, '-H', '-lnt'], [binary, '-lnt']):
        try:
            proc = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False, universal_newlines=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        ports = set()
        for line in proc.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0] in ('State', 'Netid'):
                continue
            for field in fields:
                match = re.search(r':(\d+)$', field.rstrip(']'))
                if match:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        ports.add(port)
                    break
        return ports, True
    return set(), False


def passive_port_state(port, snapshot=None):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 'unknown'
    ports, known = snapshot if snapshot is not None else passive_listening_ports()
    if not known:
        return 'unknown'
    return 'online' if port in ports else 'offline'


def inventory_online_status(client, snapshot=None):
    """Aggregate enabled-service reachability for server client list."""
    services = enabled_services(client)
    if not services:
        return 'MGMT-ONLY'
    states = [passive_port_state(svc.get('remote_port'), snapshot) for _sid, svc in services]
    if all(state == 'unknown' for state in states):
        return 'UNKNOWN'
    online = sum(1 for state in states if state == 'online')
    offline = sum(1 for state in states if state == 'offline')
    if online == len(services) and offline == 0:
        return 'ONLINE'
    if offline == len(services) and online == 0:
        return 'OFFLINE'
    if online > 0 and offline > 0:
        return 'PARTIAL'
    if online > 0:
        return 'PARTIAL'
    return 'OFFLINE'


def validate_label(value, required=False):
    text = '' if value is None else str(value).strip()
    if not text:
        if required:
            raise ValueError('client name/label is required')
        return ''
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in text):
        raise ValueError('client name/label must not contain control characters')
    if len(text) > LABEL_MAX_LEN:
        raise ValueError('client name/label must be at most %s characters' % LABEL_MAX_LEN)
    if not LABEL_RE.fullmatch(text):
        raise ValueError(
            'client name/label must start with an alphanumeric character '
            'and may contain letters, digits, space, ".", "_" and "-"'
        )
    return text


def validate_note(value):
    return validate_text_field(value, 'note', NOTE_MAX_LEN)


def validate_tag_key(value):
    text = '' if value is None else str(value).strip()
    if not text:
        raise ValueError('tag key is required')
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in text):
        raise ValueError('tag key must not contain control characters')
    if len(text) > TAG_KEY_MAX_LEN:
        raise ValueError('tag key must be at most %s characters' % TAG_KEY_MAX_LEN)
    if not TAG_KEY_RE.fullmatch(text):
        raise ValueError(
            'tag key must start with an alphanumeric character '
            'and may contain letters, digits, ".", "_" and "-"'
        )
    return text


def validate_tag_value(value):
    text = '' if value is None else str(value).strip()
    if not text:
        raise ValueError('tag value is required')
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in text):
        raise ValueError('tag value must not contain control characters')
    if len(text) > TAG_VALUE_MAX_LEN:
        raise ValueError('tag value must be at most %s characters' % TAG_VALUE_MAX_LEN)
    if not TAG_VALUE_RE.fullmatch(text):
        raise ValueError(
            'tag value must start with an alphanumeric character and may contain '
            'letters, digits, space, ".", "_", ":", "/", "@", "+", and "-"'
        )
    return text


def parse_tag_assignment(value):
    text = '' if value is None else str(value)
    if '=' not in text:
        raise ValueError('tag must use key=value format')
    key, tag_value = text.split('=', 1)
    return validate_tag_key(key), validate_tag_value(tag_value)


def client_matches_tags(client, filters):
    tags = (client or {}).get('tags') or {}
    if not isinstance(tags, dict):
        return False
    return all(tags.get(key) == value for key, value in filters)


def short_machine_id(machine_id, length=SHORT_MACHINE_ID_LEN):
    text = str(machine_id or '')
    if len(text) <= length:
        return text
    return text[:length]


def unique_short_id(machine_id, all_ids, min_len=SHORT_MACHINE_ID_LEN):
    """Shortest unique prefix of machine_id, at least min_len characters."""
    text = str(machine_id or '')
    if not text:
        return ''
    others = [str(item) for item in (all_ids or []) if str(item)]
    length = min(max(int(min_len), 1), len(text))
    while length <= len(text):
        prefix = text[:length]
        matches = [item for item in others if item.startswith(prefix)]
        if len(matches) == 1:
            return prefix
        length += 1
    return text


def display_name(client, machine_id):
    if not isinstance(client, dict):
        client = {}
    label = str(client.get('label') or '').strip()
    if label:
        return label
    hostname = str(client.get('hostname') or '').strip()
    if hostname:
        return hostname
    return short_machine_id(machine_id)


def mgmt_status(client):
    if not isinstance(client, dict):
        return 'legacy'
    status = client.get('mgmt_status')
    if status in ('enrolled', 'legacy', 'revoked'):
        return status
    if client.get('mgmt_pubkey'):
        return 'enrolled'
    return 'legacy'


def enabled_services(client):
    services = (client or {}).get('services') or {}
    if not isinstance(services, dict):
        return []
    items = []
    for sid, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if svc.get('enabled', True) is False:
            continue
        items.append((sid, svc))
    return sorted(
        items,
        key=lambda kv: (
            kv[1].get('remote_port') is None,
            kv[1].get('remote_port') or 0,
            kv[0],
        ),
    )


def first_ssh_service(client):
    for sid, svc in enabled_services(client):
        if str(svc.get('preset') or '').strip().lower() == 'ssh':
            return sid, svc
    return None, None


def sorted_clients(state):
    items = []
    for mid, client in ((state or {}).get('clients') or {}).items():
        if not isinstance(client, dict):
            continue
        items.append((str(mid), client))
    items.sort(key=lambda kv: (display_name(kv[1], kv[0]).lower(), kv[0]))
    return items


def format_candidate_table(matches):
    lines = [
        '%-10s %-18s %s' % ('CLIENT ID', 'LABEL', 'HOSTNAME'),
    ]
    mids = [item[0] for item in matches]
    for mid, client in matches:
        cid = sanitize_display(unique_short_id(mid, mids), 16)
        label = sanitize_display(client.get('label') or '-', 18)
        host = sanitize_display(client.get('hostname') or '-', 12)
        lines.append('%-10s %-18s %s' % (cid, label, host))
    return '\n'.join(lines) + '\n'


def resolve_client(state, query):
    """Resolve a client selector with CLIENT ID precedence.

    Priority:
      1. exact CLIENT ID (machine_id)
      2. unique CLIENT ID prefix
      3. exact unique label
      4. exact unique hostname

    Labels and hostnames must never shadow an actual CLIENT ID or unique
    CLIENT ID prefix (critical for destructive commands).
    """
    query = '' if query is None else str(query).strip()
    if not query:
        raise ClientLookupError('client identifier is required')
    clients = sorted_clients(state)

    exact_mid = [item for item in clients if item[0] == query]
    if len(exact_mid) == 1:
        return exact_mid[0]
    if len(exact_mid) > 1:
        raise ClientLookupError('multiple clients matched', exact_mid)

    prefix_matches = [
        item for item in clients
        if item[0].startswith(query)
    ]
    if len(prefix_matches) == 1:
        return prefix_matches[0]
    if len(prefix_matches) > 1:
        raise ClientLookupError('multiple clients matched', prefix_matches)

    label_matches = [
        item for item in clients
        if str(item[1].get('label') or '').strip().lower() == query.lower()
    ]
    if len(label_matches) == 1:
        return label_matches[0]
    if len(label_matches) > 1:
        raise ClientLookupError('multiple clients matched', label_matches)

    host_matches = [
        item for item in clients
        if str(item[1].get('hostname') or '').strip().lower() == query.lower()
    ]
    if len(host_matches) == 1:
        return host_matches[0]
    if len(host_matches) > 1:
        raise ClientLookupError('multiple clients matched', host_matches)

    raise ClientLookupError('client not found')


def find_client_id_by_label(state, label, exclude_id=None):
    """Return client id with the same label (case-insensitive), else None."""
    wanted = str(label or '').strip().lower()
    if not wanted:
        return None
    for mid, client in sorted_clients(state):
        if exclude_id and mid == exclude_id:
            continue
        if str((client or {}).get('label') or '').strip().lower() == wanted:
            return mid
    return None


def find_client_id_by_hostname(state, hostname, exclude_id=None):
    """Return client id with the same hostname (case-insensitive), else None."""
    wanted = str(hostname or '').strip().lower()
    if not wanted:
        return None
    for mid, client in sorted_clients(state):
        if exclude_id and mid == exclude_id:
            continue
        if str((client or {}).get('hostname') or '').strip().lower() == wanted:
            return mid
    return None


def resolve_client_or_exit(state, query):
    try:
        return resolve_client(state, query)
    except ClientLookupError as exc:
        if exc.matches:
            sys.stderr.write('ERROR: multiple clients matched.\n\n')
            sys.stderr.write(format_candidate_table(exc.matches))
            sys.stderr.write('\nUse a longer CLIENT ID prefix.\n')
        elif str(exc) == 'client not found':
            shown = sanitize_display(query, 128)
            sys.stderr.write('ERROR: client not found: %s\n' % shown)
            sys.stderr.write('\nUse a CLIENT ID, unique label, or unique hostname.\n')
            sys.stderr.write('Run:\n  client list\n\nor:\n  client show ?\n')
        else:
            sys.stderr.write('ERROR: %s\n' % exc)
        raise SystemExit(1)


def seed_admin_metadata(client, label=None, note=None):
    """Set label/note only when empty; never modify server-owned tags or groups."""
    if not isinstance(client, dict):
        return client
    incoming_label = str(label or '').strip()
    incoming_note = str(note or '').strip()
    existing_label = str(client.get('label') or '').strip()
    existing_note = str(client.get('note') or '').strip()
    if incoming_label and not existing_label:
        client['label'] = incoming_label
    if incoming_note and not existing_note:
        client['note'] = incoming_note
    return client


def is_reserved_group_name(name):
    return str(name or '').strip().lower() in RESERVED_GROUP_NAMES


def validate_group_name(value, required=True):
    text = '' if value is None else str(value).strip()
    if not text:
        if required:
            raise ValueError('group name is required')
        return ''
    if any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in text):
        raise ValueError('group name must not contain control characters')
    if len(text) > GROUP_NAME_MAX_LEN:
        raise ValueError('group name must be at most %s characters' % GROUP_NAME_MAX_LEN)
    if not GROUP_NAME_RE.fullmatch(text):
        raise ValueError(
            'group name must start with an alphanumeric character '
            'and may contain letters, digits, ".", "_" and "-"'
        )
    if is_reserved_group_name(text):
        raise ValueError('group name %r is reserved' % text)
    return text


def validate_group_description(value):
    return validate_text_field(value, 'group description', GROUP_DESCRIPTION_MAX_LEN)


def validate_group_id(value, required=True):
    text = '' if value is None else str(value).strip()
    if not text:
        if required:
            raise ValueError('group id is required')
        return ''
    if not GROUP_ID_RE.fullmatch(text):
        raise ValueError('group id must match grp_<8 lowercase hex>')
    return text


def ensure_groups_map(state):
    if not isinstance(state, dict):
        return {}
    groups = state.get('groups')
    if groups is None:
        return {}
    if not isinstance(groups, dict):
        raise ValueError('registry groups must be an object')
    return groups


def normalize_group_ids(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError('client group_ids must be a list')
    result = []
    for item in value:
        gid = validate_group_id(item)
        if gid not in result:
            result.append(gid)
    return result


def client_group_ids(client):
    """Return normalized group IDs.

    Malformed membership fails closed (raises ValueError) so show/filter
    paths cannot silently present corrupted state as ungrouped.
    """
    return normalize_group_ids((client or {}).get('group_ids'))


def set_client_group_ids(client, group_ids):
    ids = normalize_group_ids(group_ids)
    if ids:
        client['group_ids'] = ids
    else:
        client.pop('group_ids', None)
    return client


def generate_group_id(existing_ids=None):
    existing = set(str(item) for item in (existing_ids or []))
    for _ in range(64):
        gid = GROUP_ID_PREFIX + secrets.token_hex(GROUP_ID_HEX_LEN // 2)
        if gid not in existing:
            return gid
    raise RuntimeError('unable to allocate unique group id')


def sorted_groups(state):
    groups = ensure_groups_map(state)
    result = [
        (str(gid), group)
        for gid, group in groups.items()
        if isinstance(group, dict)
    ]
    result.sort(key=lambda item: (str(item[1].get('name') or '').lower(), item[0]))
    return result


def system_group_meta(name):
    return {'name': str(name).lower(), 'type': 'system'}


def format_group_candidate_table(matches):
    lines = ['%-14s %s' % ('GROUP ID', 'NAME')]
    for gid, group in matches:
        lines.append('%-14s %s' % (
            sanitize_display(gid, 14),
            sanitize_display((group or {}).get('name') or '-', 64),
        ))
    return '\n'.join(lines) + '\n'


def resolve_group(state, query):
    """Resolve exact ID, unique ID prefix, then unique exact name."""
    query = str(query or '').strip()
    if not query:
        raise GroupLookupError('group identifier is required')
    lower = query.lower()
    if lower in RESERVED_GROUP_NAMES:
        return lower, system_group_meta(lower)
    groups = sorted_groups(state)
    exact = [item for item in groups if item[0] == query]
    if exact:
        return exact[0]
    prefixes = [item for item in groups if item[0].startswith(query)]
    if len(prefixes) == 1:
        return prefixes[0]
    if len(prefixes) > 1:
        raise GroupLookupError('multiple groups matched', prefixes)
    names = [
        item for item in groups
        if str(item[1].get('name') or '').strip().lower() == lower
    ]
    if len(names) == 1:
        return names[0]
    if len(names) > 1:
        raise GroupLookupError('multiple groups matched', names)
    raise GroupLookupError('group not found')


def resolve_group_or_exit(state, query):
    try:
        return resolve_group(state, query)
    except GroupLookupError as exc:
        if exc.matches:
            sys.stderr.write('ERROR: multiple groups matched.\n\n')
            sys.stderr.write(format_group_candidate_table(exc.matches))
            sys.stderr.write('\nUse a longer GROUP ID prefix.\n')
        else:
            sys.stderr.write('ERROR: %s: %s\n' % (exc, sanitize_display(query, 128)))
        raise SystemExit(1)


def resolve_manual_group_or_exit(state, query):
    gid, group = resolve_group_or_exit(state, query)
    if gid in RESERVED_GROUP_NAMES:
        sys.stderr.write('ERROR: system groups cannot be modified or assigned\n')
        raise SystemExit(1)
    return gid, group


def find_group_id_by_name(state, name, exclude_id=None):
    wanted = str(name or '').strip().lower()
    if not wanted:
        return None
    for gid, group in sorted_groups(state):
        if gid != exclude_id and str(group.get('name') or '').strip().lower() == wanted:
            return gid
    return None


def client_matches_group(state, client, selector):
    if selector == SYSTEM_GROUP_ALL:
        return True
    try:
        ids = client_group_ids(client)
    except ValueError:
        # Malformed membership is never silently treated as ungrouped.
        return False
    if selector == SYSTEM_GROUP_UNGROUPED:
        return not ids
    return selector in ids


def clients_in_group(state, selector):
    gid, _group = resolve_group(state, selector)
    return [
        (mid, client)
        for mid, client in sorted_clients(state)
        if client_matches_group(state, client, gid)
    ]


def group_member_count(state, selector):
    return len(clients_in_group(state, selector))


def client_group_memberships(state, client):
    """Return known memberships; raise ValueError on malformed or dangling IDs."""
    groups = ensure_groups_map(state)
    ids = client_group_ids(client)
    out = []
    dangling = []
    for gid in ids:
        group = groups.get(gid)
        if isinstance(group, dict):
            out.append((gid, group))
        else:
            dangling.append(gid)
    if dangling:
        raise ValueError(
            'client references unknown group id(s): %s' % ', '.join(dangling)
        )
    return out


def apply_observed_fields(client, hostname=None, source_ip=None, seen_at=None):
    if not isinstance(client, dict):
        return client
    host = validate_hostname(hostname)
    if host:
        client['hostname'] = host
    when = seen_at or utc_now_iso()
    client['last_seen_at'] = when
    ip = normalize_ip(source_ip) if source_ip else None
    if ip:
        if not str(client.get('first_seen_ip') or '').strip():
            client['first_seen_ip'] = ip
        client['last_source_ip'] = ip
    return client


def atomic_write_json(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    try:
        path.chmod(mode)
    except OSError:
        pass


def load_server_registry(root=None):
    if root is None:
        root = os.environ.get('FRP_DEPLOY_TEST_ROOT', '')
    cfg_path = Path(str(root) + '/etc/drlink/config.json')
    cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
    path = Path(cfg['registry_file'])
    if root and not str(path).startswith(str(root)):
        path = Path(str(root) + str(path))
    if not path.exists():
        raise FileNotFoundError(
            'registry.json is missing (authoritative registry state required)'
        )
    state = json.loads(path.read_text(encoding='utf-8'))
    return cfg, path, state
