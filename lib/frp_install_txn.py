#!/usr/bin/env python3
"""Pre-cutover snapshot and restore for the server installer.

Never rotates or deletes CA material, the FRP token, the registry, or
reservations. Those paths are excluded from both snapshot and restore.

Managed project-file lists come from server-project-files.manifest.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from frp_project_files import protected_exact, protected_prefixes, snapshot_rels

PROTECTED_EXACT = protected_exact()
PROTECTED_PREFIXES = protected_prefixes()
SNAPSHOT_RELS = tuple(snapshot_rels())

UNIT_NAMES = (
    'drlink-server.service',
    'drlink-allocator.service',
    'drlink-access.service',
    'drlink-frontend.service',
)


def _is_protected(rel):
    rel = rel.lstrip('/')
    if rel in PROTECTED_EXACT:
        return True
    return any(rel.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _systemctl_executable():
    hook = os.environ.get('FRP_INSTALL_TXN_HOOK_SYSTEMCTL')
    if hook:
        return hook
    return shutil.which('systemctl')


def _query_host_systemd():
    """Avoid touching host systemd from fixture trees unless a mock is injected."""
    if os.environ.get('FRP_INSTALL_TXN_HOOK_SYSTEMCTL'):
        return True
    if os.environ.get('FRP_SERVER_TEST_ROOT'):
        return False
    return _systemctl_executable() is not None


def _run_systemctl_query(args, timeout=5):
    exe = _systemctl_executable()
    if not exe:
        return None
    try:
        return subprocess.run(
            [exe, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _unit_existed_from_load(load_state):
    return load_state in ('loaded', 'masked', 'stub')


def _unit_existed(item):
    """Whether the unit existed before the transaction.

    Fresh-install units are typically LoadState=not-found while
    ``systemctl is-active`` still prints ``inactive``. Absence itself is
    the restored state; do not treat that inactive result as "must stop".
    """
    if item.get('existed') is not None:
        return bool(item.get('existed'))
    load_state = item.get('load_state')
    if load_state is not None:
        return _unit_existed_from_load(load_state)
    enabled = item.get('enabled')
    if enabled in (None, 'not-found'):
        return False
    return True


def _unit_state(unit):
    """Best-effort enabled/active/existence capture. Never raises."""
    state = {
        'unit': unit,
        'enabled': None,
        'active': None,
        'load_state': None,
        'existed': False,
    }
    if not _systemctl_executable():
        return state
    try:
        loaded = _run_systemctl_query(['show', '-p', 'LoadState', '--value', unit])
        if loaded is not None:
            state['load_state'] = (loaded.stdout or '').strip() or None
            state['existed'] = _unit_existed_from_load(state['load_state'])
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        enabled = _run_systemctl_query(['is-enabled', unit])
        if enabled is not None:
            state['enabled'] = (enabled.stdout or '').strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        active = _run_systemctl_query(['is-active', unit])
        if active is not None:
            state['active'] = (active.stdout or '').strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    if not state['existed'] and state.get('enabled') not in (None, 'not-found'):
        # Some systemd versions report is-enabled before LoadState is useful.
        state['existed'] = True
    return state


def capture_service_states(root):
    """Capture project unit and nginx ownership-relevant service state."""
    root = Path(root)
    if not _query_host_systemd():
        return {'units': [], 'skipped': True}
    units = [_unit_state(name) for name in UNIT_NAMES]
    nginx = _unit_state('nginx.service')
    return {'units': units, 'nginx': nginx, 'skipped': False}


def snapshot(root, dest, extra=None):
    root = Path(root)
    dest = Path(dest)
    files_dir = dest / 'files'
    files_dir.mkdir(parents=True, exist_ok=True)
    present = []
    absent = []
    for rel in SNAPSHOT_RELS:
        if _is_protected(rel):
            continue
        src = root / rel
        if src.is_file():
            target = files_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(target))
            os.chmod(target, _mode(src))
            present.append({'path': rel, 'mode': _mode(src)})
        else:
            absent.append(rel)
    service_states = capture_service_states(root)
    meta = {
        'present': present,
        'absent': absent,
        'services': service_states,
        'extra': extra or {},
    }
    (dest / 'metadata.json').write_text(
        json.dumps(meta, indent=2, sort_keys=True) + '\n', encoding='utf-8'
    )
    os.chmod(dest / 'metadata.json', 0o600)
    return meta


def restore(root, dest):
    root = Path(root)
    dest = Path(dest)
    meta_path = dest / 'metadata.json'
    if not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text(encoding='utf-8'))
    files_dir = dest / 'files'
    for item in meta.get('present') or []:
        rel = str(item.get('path') or '')
        if not rel or _is_protected(rel):
            continue
        src = files_dir / rel
        if not src.is_file():
            continue
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + '.restore.tmp')
        shutil.copy2(str(src), str(tmp))
        mode = int(item.get('mode') or _mode(src))
        os.chmod(tmp, mode)
        tmp.replace(target)
    for rel in meta.get('absent') or []:
        rel = str(rel or '')
        if not rel or _is_protected(rel):
            continue
        target = root / rel
        if target.is_file() or target.is_symlink():
            target.unlink()
    return meta


def _systemctl(args, timeout=30):
    if os.environ.get('FRP_INSTALL_TXN_HOOK_SYSTEMD_FAIL') == '1':
        return False
    exe = _systemctl_executable()
    if not exe:
        return False
    try:
        result = subprocess.run(
            [exe, *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _restore_enabled(unit, enabled):
    if enabled in ('enabled', 'enabled-runtime'):
        return _systemctl(['enable', unit], timeout=30)
    if enabled in ('disabled', 'disabled-runtime'):
        return _systemctl(['disable', unit], timeout=30)
    return True


def _restore_active(unit, item):
    existed = _unit_existed(item)
    active = item.get('active')
    if not existed:
        # Fresh-install / previously absent: unit files were already removed.
        # reset-failed clears leftover NAMESPACE/start failures; ignore not-found.
        _systemctl(['reset-failed', unit], timeout=30)
        current = _unit_state(unit)
        if current.get('active') != 'active':
            return True
        if not _systemctl(['stop', unit], timeout=60):
            current = _unit_state(unit)
            return current.get('active') != 'active'
        current = _unit_state(unit)
        return current.get('active') != 'active'
    if active == 'active':
        return _systemctl(['restart', unit], timeout=60)
    if active in ('inactive', 'failed'):
        if not _systemctl(['stop', unit], timeout=60):
            return False
        current = _unit_state(unit)
        return current.get('active') != 'active'
    return True


def apply_service_states(meta, skip=False):
    """Restore enabled/active semantics for project units after file restore."""
    if skip or not meta:
        return True
    services = meta.get('services') or {}
    if services.get('skipped'):
        return True
    if not _systemctl_executable():
        return True
    if not _systemctl(['daemon-reload'], timeout=30):
        return False
    for item in services.get('units') or []:
        unit = str(item.get('unit') or '')
        if not unit:
            continue
        if _unit_existed(item):
            if not _restore_enabled(unit, item.get('enabled')):
                return False
        if not _restore_active(unit, item):
            return False
    nginx = services.get('nginx') or {}
    if nginx:
        if _unit_existed(nginx):
            if not _restore_enabled('nginx.service', nginx.get('enabled')):
                return False
        if not _restore_active('nginx.service', nginx):
            return False
    return True


def verify_service_states(meta, skip=False):
    if skip or not meta:
        return True
    services = meta.get('services') or {}
    if services.get('skipped'):
        return True
    if not _systemctl_executable():
        return True
    for item in services.get('units') or []:
        unit = str(item.get('unit') or '')
        if not unit:
            continue
        current = _unit_state(unit)
        if not _unit_existed(item):
            if current.get('active') == 'active':
                return False
            continue
        expected_enabled = item.get('enabled')
        expected_active = item.get('active')
        if expected_enabled in ('enabled', 'enabled-runtime'):
            if current.get('enabled') not in ('enabled', 'enabled-runtime', 'static'):
                return False
        if expected_active == 'active' and current.get('active') != 'active':
            return False
        if expected_active in ('inactive', 'failed') and current.get('active') == 'active':
            return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description='Server installer snapshot/restore')
    parser.add_argument('action', choices=('snapshot', 'restore'))
    parser.add_argument('--root', required=True)
    parser.add_argument('--dest', required=True)
    parser.add_argument(
        '--apply-services',
        action='store_true',
        help='After restore, re-apply captured unit enabled/active state',
    )
    args = parser.parse_args(argv)
    if args.action == 'snapshot':
        snapshot(args.root, args.dest)
        return 0
    meta = restore(args.root, args.dest)
    if meta is None:
        sys.stderr.write('ERROR: install snapshot metadata is missing\n')
        return 1
    skip = bool(os.environ.get('FRP_SERVER_TEST_ROOT')) and not os.environ.get(
        'FRP_INSTALL_TXN_HOOK_SYSTEMCTL'
    )
    if args.apply_services:
        if not apply_service_states(meta, skip=skip):
            sys.stderr.write('ERROR: service-state restoration failed\n')
            return 1
        if not verify_service_states(meta, skip=skip):
            sys.stderr.write('ERROR: restored service state verification failed\n')
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
