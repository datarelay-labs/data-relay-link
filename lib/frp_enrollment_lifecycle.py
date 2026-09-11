#!/usr/bin/env python3
"""Enrollment retention, purge, and pair-aware cleanup helpers."""
from __future__ import annotations

import fcntl
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_RETENTION_DAYS = 30
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
RETENTION_CLEANUP_MIN_INTERVAL = 3600
SECONDS_PER_DAY = 86400

TERMINAL_STATES = frozenset({'expired', 'completed', 'revoked'})
ACTIVE_STATES = frozenset({'pending', 'bound'})

_last_retention_cleanup = 0.0


class EnrollmentLifecycleError(Exception):
    pass


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def parse_epoch(value):
    if value in (None, ''):
        return 0, True
    try:
        return int(value), True
    except (TypeError, ValueError):
        return 0, False


def parse_timestamp(value):
    """Return (epoch, valid). Missing values return (None, True)."""
    if value in (None, ''):
        return None, True
    if isinstance(value, bool):
        return None, False
    if isinstance(value, float):
        if not value.is_integer():
            return None, False
        try:
            return int(value), True
        except (TypeError, ValueError, OverflowError):
            return None, False
    if isinstance(value, int):
        return int(value), True
    text = str(value).strip()
    if not text:
        return None, True
    try:
        return int(text), True
    except ValueError:
        pass
    try:
        if text.endswith('Z'):
            text = text[:-1] + '+00:00'
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp()), True
    except (ValueError, OverflowError, OSError):
        return None, False


def retention_days_from_config(cfg):
    """Return validated retention days. Unset config key → default 30."""
    if not isinstance(cfg, dict) or 'enrollment_retention_days' not in cfg:
        return DEFAULT_RETENTION_DAYS
    raw = cfg.get('enrollment_retention_days')
    if raw is None:
        return DEFAULT_RETENTION_DAYS
    if isinstance(raw, bool) or isinstance(raw, float):
        raise EnrollmentLifecycleError(
            'ERROR: enrollment_retention_days must be an integer between %s and %s'
            % (MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
        )
    if isinstance(raw, int):
        days = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if not text or text[0] == '-' or not text.isdigit():
            raise EnrollmentLifecycleError(
                'ERROR: enrollment_retention_days must be an integer between %s and %s'
                % (MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
            )
        days = int(text)
    else:
        raise EnrollmentLifecycleError(
            'ERROR: enrollment_retention_days must be an integer between %s and %s'
            % (MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
        )
    if days < MIN_RETENTION_DAYS or days > MAX_RETENTION_DAYS:
        raise EnrollmentLifecycleError(
            'ERROR: enrollment_retention_days must be an integer between %s and %s'
            % (MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
        )
    return days


def normalize_state(record, now):
    """Map record fields to pending|bound|completed|expired|revoked|invalid.

    Enrollment completion (used_at) and bootstrap completion (completed_at)
    both normalize to 'completed' so pair-aware cleanup can compare states.
    """
    if not isinstance(record, dict):
        return 'invalid'
    if record.get('revoked_at'):
        return 'revoked'
    if record.get('completed_at'):
        return 'completed'
    if record.get('used_at'):
        return 'completed'
    expires, valid = parse_epoch(record.get('expires_at'))
    if not valid:
        return 'invalid'
    if expires and expires < now:
        return 'expired'
    if record.get('bound_machine_id'):
        return 'bound'
    return 'pending'


def terminal_timestamp(record, state, now=None):
    """Authoritative terminal timestamp for retention (epoch) or None if unknown.

    completed → completed_at / used_at
    revoked   → revoked_at
    expired   → expires_at
    """
    del now  # retained for call-site compatibility
    if state not in TERMINAL_STATES:
        return None
    if state == 'expired':
        ts, valid = parse_epoch(record.get('expires_at'))
        if not valid or not ts:
            return None
        return ts
    if state == 'completed':
        for key in ('completed_at', 'used_at'):
            ts, valid = parse_timestamp(record.get(key))
            if not valid:
                return None
            if ts is not None:
                return ts
        return None
    if state == 'revoked':
        ts, valid = parse_timestamp(record.get('revoked_at'))
        if not valid or ts is None:
            return None
        return ts
    return None


def _load_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _pair_states_consistent(ticket_state, enroll_state):
    if ticket_state == 'invalid' or enroll_state == 'invalid':
        return False
    if ticket_state in ACTIVE_STATES and enroll_state in ACTIVE_STATES:
        # Bound ticket may precede enrollment binding (same-machine retry path).
        if ticket_state == 'bound' and enroll_state == 'pending':
            return True
        return ticket_state == enroll_state
    if ticket_state in TERMINAL_STATES and enroll_state in TERMINAL_STATES:
        return ticket_state == enroll_state
    return False


def _validate_zero_touch_pair(ticket_rec, enroll_rec, ticket_path, enroll_path, enrollment_map):
    del ticket_path, enroll_path  # paths retained for call-site clarity
    eid = str(ticket_rec.get('enrollment_id') or '').strip().lower()
    if not eid:
        return 'bootstrap ticket has no enrollment_id'
    duplicates = enrollment_map.get(eid) or []
    if len(duplicates) > 1:
        return 'enrollment is paired to multiple bootstrap tickets'
    if enroll_rec is None:
        return 'bootstrap ticket points to missing enrollment record'
    if not isinstance(enroll_rec, dict):
        return 'paired enrollment record is malformed'
    ticket_eid = str(ticket_rec.get('enrollment_id') or '').strip().lower()
    enroll_id = str(enroll_rec.get('id') or '').strip().lower()
    if ticket_eid != enroll_id:
        return 'bootstrap ticket enrollment_id does not match paired enrollment id'
    now = int(time.time())
    ticket_state = normalize_state(ticket_rec, now)
    enroll_state = normalize_state(enroll_rec, now)
    if not _pair_states_consistent(ticket_state, enroll_state):
        return 'bootstrap ticket and paired enrollment states are inconsistent'
    return None


def collect_logical_enrollments(enrollments_dir, bootstrap_dir, now=None):
    """Return logical enrollment rows (manual + deduplicated zero-touch)."""
    now = int(now if now is not None else time.time())
    enrollments_dir = Path(enrollments_dir)
    bootstrap_dir = Path(bootstrap_dir)

    enrollment_map = {}
    ticket_records = []
    if bootstrap_dir.is_dir():
        for path in bootstrap_dir.glob('*.json'):
            rec = _load_json(path)
            if not isinstance(rec, dict):
                continue
            eid = str(rec.get('enrollment_id') or '').strip().lower()
            if eid:
                enrollment_map.setdefault(eid, []).append(path)
            ticket_records.append((path, rec))

    paired_enrollment_ids = set(enrollment_map)
    rows = []

    for ticket_path, ticket_rec in ticket_records:
        ticket_id = str(ticket_rec.get('id') or ticket_path.stem).strip().lower()
        eid = str(ticket_rec.get('enrollment_id') or '').strip().lower()
        enroll_path = enrollments_dir / (eid + '.json') if eid else None
        enroll_rec = _load_json(enroll_path) if enroll_path and enroll_path.is_file() else None
        pair_error = _validate_zero_touch_pair(
            ticket_rec, enroll_rec, ticket_path, enroll_path, enrollment_map
        )
        state = normalize_state(ticket_rec, now)
        terminal_at = terminal_timestamp(ticket_rec, state, now)
        if state in TERMINAL_STATES and terminal_at is None and not pair_error:
            pair_error = 'terminal zero-touch record has malformed timestamp'
        rows.append({
            'id': ticket_id,
            'type': 'zero-touch',
            'state': state,
            'terminal_at': terminal_at,
            'ticket_path': ticket_path,
            'enroll_path': enroll_path if enroll_path and enroll_path.is_file() else None,
            'ticket_record': ticket_rec,
            'enroll_record': enroll_rec,
            'pair_error': pair_error,
        })

    if enrollments_dir.is_dir():
        for path in enrollments_dir.glob('*.json'):
            rec = _load_json(path)
            if not isinstance(rec, dict):
                continue
            raw_id = str(rec.get('id') or path.stem).strip().lower()
            if not raw_id or raw_id in paired_enrollment_ids:
                continue
            state = normalize_state(rec, now)
            terminal_at = terminal_timestamp(rec, state, now)
            pair_error = None
            if state in TERMINAL_STATES and terminal_at is None:
                pair_error = 'terminal manual enrollment has malformed timestamp'
            rows.append({
                'id': raw_id,
                'type': 'manual',
                'state': state,
                'terminal_at': terminal_at,
                'ticket_path': None,
                'enroll_path': path,
                'ticket_record': None,
                'enroll_record': rec,
                'pair_error': pair_error,
            })

    rows.sort(
        key=lambda row: (
            (row.get('ticket_record') or row.get('enroll_record') or {}).get('created_at', ''),
            row['id'],
        )
    )
    return rows


def is_retention_eligible(row, now, retention_days):
    if row.get('pair_error'):
        return False
    state = row.get('state')
    if state not in TERMINAL_STATES:
        return False
    terminal_at = row.get('terminal_at')
    if terminal_at is None:
        return False
    cutoff = now - (int(retention_days) * SECONDS_PER_DAY)
    return terminal_at <= cutoff


def is_bulk_purge_eligible(row, now, older_than_days):
    return is_retention_eligible(row, now, older_than_days)


def resolve_target(rows, target_id):
    target_id = str(target_id or '').strip().lower()
    matches = [row for row in rows if row['id'] == target_id]
    if matches:
        return matches[0]
    for row in rows:
        enroll_rec = row.get('enroll_record') or {}
        if str(enroll_rec.get('id') or '').strip().lower() == target_id:
            return row
    return None


def _stage_delete(path):
    """Rename original → *.purging. Returns staged path or None if absent."""
    if path is None or not Path(path).is_file():
        return None
    path = Path(path)
    staged = path.with_suffix(path.suffix + '.purging')
    os.replace(path, staged)
    return staged


def _commit_staged_deletes(staged_paths):
    """Unlink tombstones (garbage collection only). Never rolls back originals."""
    errors = []
    for staged in staged_paths:
        if staged is None:
            continue
        try:
            Path(staged).unlink(missing_ok=True)
        except OSError as exc:
            errors.append('%s: %s' % (staged, exc))
    return errors


def _rollback_staged(staged_paths):
    """Restore originals from *.purging. Only valid BEFORE the commit point."""
    for staged in staged_paths:
        if staged is None:
            continue
        staged = Path(staged)
        if not staged.is_file():
            continue
        if str(staged).endswith('.purging'):
            original = Path(str(staged)[: -len('.purging')])
        else:
            original = staged
        try:
            os.replace(staged, original)
        except OSError:
            pass


def _delete_targets(row):
    """Pair-aware filesystem delete with an explicit commit point.

    Before commit (all renames to *.purging succeed):
      any rename failure → restore every staged original.
    After commit:
      unlink is GC only; unlink failure leaves *.purging tombstones
      and must NOT restore half the pair.
    """
    staged = []
    targets = []
    if row.get('enroll_path'):
        targets.append(row['enroll_path'])
    if row.get('ticket_path'):
        targets.append(row['ticket_path'])
    try:
        for path in targets:
            staged.append(_stage_delete(path))
    except Exception:
        # Pre-commit: restore anything already staged.
        _rollback_staged(staged)
        raise
    # Commit point: every original has been renamed to a tombstone.
    # Logical deletion is complete even if unlinks fail.
    _commit_staged_deletes(staged)


def reconcile_stale_tombstones(enrollments_dir, bootstrap_dir):
    """Unlink leftover *.json.purging tombstones from prior GC failures."""
    removed = 0
    for base in (enrollments_dir, bootstrap_dir):
        base = Path(base) if base else None
        if base is None or not base.is_dir():
            continue
        for path in base.glob('*.json.purging'):
            try:
                path.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
    return removed


def _registry_lock(registry_file):
    registry_file = Path(registry_file)
    lock_path = registry_file.parent / 'registry.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    return lock_fd


def _release_lock(lock_fd):
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _safe_audit_details(row, state, reason, retention_days=None):
    details = {
        'enrollment_id': row.get('id'),
        'type': row.get('type'),
        'previous_state': state,
        'reason': reason,
    }
    if retention_days is not None:
        details['retention_days'] = int(retention_days)
    return details


def purge_enrollment_row(row, *, audit_emit=None, reason='manual', retention_days=None):
    state = row.get('state')
    if state in ACTIVE_STATES:
        raise EnrollmentLifecycleError(
            'ERROR: active enrollment cannot be purged.\n'
            'Revoke it first:\n'
            '  drlink enrollment revoke %s' % row.get('id')
        )
    if state not in TERMINAL_STATES:
        raise EnrollmentLifecycleError('ERROR: enrollment is not in a terminal state')
    if row.get('pair_error'):
        raise EnrollmentLifecycleError('ERROR: %s' % row['pair_error'])
    had_ticket = bool(row.get('ticket_path'))
    _delete_targets(row)
    if audit_emit:
        details = _safe_audit_details(row, state, reason, retention_days=retention_days)
        audit_emit('enrollment.purged', details=details)
        if had_ticket:
            audit_emit(
                'bootstrap.purged',
                details={
                    'ticket_id': row.get('id'),
                    'previous_state': state,
                    'reason': reason,
                },
            )


def purge_enrollment_by_id(
    target_id,
    enrollments_dir,
    bootstrap_dir,
    registry_file,
    *,
    audit_emit=None,
    now=None,
):
    now = int(now if now is not None else time.time())
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
    row = resolve_target(rows, target_id)
    if row is None:
        raise EnrollmentLifecycleError('ERROR: enrollment not found')
    lock_fd = _registry_lock(registry_file)
    try:
        rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
        row = resolve_target(rows, target_id)
        if row is None:
            raise EnrollmentLifecycleError('ERROR: enrollment not found')
        purge_enrollment_row(row, audit_emit=audit_emit, reason='manual')
    finally:
        _release_lock(lock_fd)
    return row


def preview_bulk_purge(enrollments_dir, bootstrap_dir, older_than_days, now=None):
    now = int(now if now is not None else time.time())
    if isinstance(older_than_days, bool) or isinstance(older_than_days, float):
        raise EnrollmentLifecycleError('ERROR: --older-than requires a positive integer number of days')
    try:
        days = int(older_than_days)
    except (TypeError, ValueError):
        raise EnrollmentLifecycleError('ERROR: --older-than requires a positive integer number of days')
    if days < 1:
        raise EnrollmentLifecycleError('ERROR: --older-than requires a positive integer number of days')
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
    matched = [row for row in rows if is_bulk_purge_eligible(row, now, days)]
    counts = {'expired': 0, 'completed': 0, 'revoked': 0}
    for row in matched:
        state = row.get('state')
        if state in counts:
            counts[state] += 1
    return {
        'older_than_days': days,
        'matched': matched,
        'counts': counts,
        'total': len(matched),
    }


def bulk_purge_enrollments(
    enrollments_dir,
    bootstrap_dir,
    registry_file,
    older_than_days,
    *,
    audit_emit=None,
    now=None,
):
    preview = preview_bulk_purge(enrollments_dir, bootstrap_dir, older_than_days, now=now)
    now = int(now if now is not None else time.time())
    lock_fd = _registry_lock(registry_file)
    purged = 0
    try:
        rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
        matched = [row for row in rows if is_bulk_purge_eligible(row, now, preview['older_than_days'])]
        for row in matched:
            purge_enrollment_row(
                row,
                audit_emit=audit_emit,
                reason='manual',
                retention_days=preview['older_than_days'],
            )
            purged += 1
    finally:
        _release_lock(lock_fd)
    return purged, preview


def run_retention_cleanup_locked(
    enrollments_dir,
    bootstrap_dir,
    registry_file,
    retention_days,
    *,
    audit_emit=None,
    now=None,
):
    """Run retention cleanup assuming the caller already owns registry.lock.

    Never reacquires registry.lock. Callers that hold the allocator FileLock
    (or any other exclusive flock on registry.lock) MUST use this entry point
    — Linux flock is not recursive across independent file descriptors.

    Lock order (allocator HTTP writers):
      1. in-process LOCK (threading)
      2. registry.lock
      3. retention cleanup (this function; no additional flock)
      4. enrollment / bootstrap / nonce writes under the same registry.lock
    """
    del registry_file  # retained for call-site symmetry with the locking wrapper
    now = int(now if now is not None else time.time())
    reconcile_stale_tombstones(enrollments_dir, bootstrap_dir)
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
    eligible = [row for row in rows if is_retention_eligible(row, now, retention_days)]
    purged = 0
    for row in eligible:
        purge_enrollment_row(
            row,
            audit_emit=audit_emit,
            reason='retention',
            retention_days=retention_days,
        )
        purged += 1
    if audit_emit and purged:
        audit_emit(
            'enrollment.retention_cleanup',
            details={
                'purged': purged,
                'retention_days': int(retention_days),
                'actor': 'retention-cleanup',
            },
        )
    return {'purged': purged}


def run_retention_cleanup(
    enrollments_dir,
    bootstrap_dir,
    registry_file,
    retention_days,
    *,
    audit_emit=None,
    now=None,
):
    """Acquire registry.lock then run retention cleanup.

    Prefer run_retention_cleanup_locked when the caller already holds the lock.
    """
    now = int(now if now is not None else time.time())
    # Cheap pre-check without the lock; re-check under the lock.
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
    eligible = [row for row in rows if is_retention_eligible(row, now, retention_days)]
    # Always reconcile tombstones (may exist with zero eligible rows).
    needs_lock = bool(eligible)
    if not needs_lock:
        # Still need the lock briefly if tombstones may exist; cheap path:
        # attempt tombstone GC under the lock only when any .purging is present.
        for base in (enrollments_dir, bootstrap_dir):
            base = Path(base) if base else None
            if base is not None and base.is_dir() and any(base.glob('*.json.purging')):
                needs_lock = True
                break
    if not needs_lock:
        return {'purged': 0, 'skipped_pairs': 0}
    lock_fd = _registry_lock(registry_file)
    try:
        return run_retention_cleanup_locked(
            enrollments_dir,
            bootstrap_dir,
            registry_file,
            retention_days,
            audit_emit=audit_emit,
            now=now,
        )
    finally:
        _release_lock(lock_fd)


def maybe_run_retention_cleanup(
    cfg,
    *,
    force=False,
    audit_emit=None,
    now=None,
    already_locked=False,
):
    """Throttle wrapper around retention cleanup.

    already_locked=True: caller owns registry.lock; never reacquire (use
    run_retention_cleanup_locked). Required for allocator redeem / enroll
    paths that already hold FileLock(registry.lock).
    """
    global _last_retention_cleanup
    now_ts = time.time()
    if not force and now_ts - _last_retention_cleanup < RETENTION_CLEANUP_MIN_INTERVAL:
        return {'skipped': True, 'purged': 0}
    retention_days = retention_days_from_config(cfg)
    enrollments_dir = cfg.get('enrollments_dir')
    if not enrollments_dir:
        return {'skipped': True, 'purged': 0}
    bootstrap_dir = cfg.get('bootstrap_dir') or str(Path(enrollments_dir).parent / 'bootstrap')
    registry_file = cfg.get('registry_file') or str(Path(enrollments_dir).parent / 'registry.json')
    if already_locked:
        result = run_retention_cleanup_locked(
            enrollments_dir,
            bootstrap_dir,
            registry_file,
            retention_days,
            audit_emit=audit_emit,
            now=now,
        )
    else:
        result = run_retention_cleanup(
            enrollments_dir,
            bootstrap_dir,
            registry_file,
            retention_days,
            audit_emit=audit_emit,
            now=now,
        )
    _last_retention_cleanup = now_ts
    result['skipped'] = False
    return result


def load_audit_emit():
    try:
        import importlib.util
        here = Path(__file__).resolve()
        for path in (
            here.parent / 'frp_audit.py',
            Path('/usr/local/lib/drlink/frp_audit.py'),
        ):
            if path.is_file():
                spec = importlib.util.spec_from_file_location('frp_audit', str(path))
                audit = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(audit)
                return audit.try_emit
    except Exception:
        pass
    return None


def retention_status(enrollments_dir, bootstrap_dir, retention_days, now=None):
    """Read-only summary counts for doctor / diagnostics."""
    now = int(now if now is not None else time.time())
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)
    active = 0
    terminal = 0
    eligible = 0
    ambiguous = 0
    for row in rows:
        if row.get('pair_error'):
            ambiguous += 1
        state = row.get('state')
        if state in ACTIVE_STATES:
            active += 1
        elif state in TERMINAL_STATES:
            terminal += 1
            if is_retention_eligible(row, now, retention_days):
                eligible += 1
    return {
        'retention_days': int(retention_days),
        'active': active,
        'terminal': terminal,
        'eligible': eligible,
        'ambiguous': ambiguous,
        'total': len(rows),
    }


def doctor_scan_enrollment_lifecycle(enrollments_dir, bootstrap_dir, retention_days, now=None):
    """Read-only lifecycle diagnostics for doctor."""
    now = int(now if now is not None else time.time())
    findings = []
    rows = collect_logical_enrollments(enrollments_dir, bootstrap_dir, now)

    enrollment_map = {}
    if Path(bootstrap_dir).is_dir():
        for path in Path(bootstrap_dir).glob('*.json'):
            rec = _load_json(path)
            if not isinstance(rec, dict):
                findings.append(('orphan_bootstrap_ticket', str(path.name), 'malformed bootstrap ticket JSON'))
                continue
            eid = str(rec.get('enrollment_id') or '').strip().lower()
            if eid:
                enrollment_map.setdefault(eid, []).append(str(path.name))

    for eid, tickets in enrollment_map.items():
        if len(tickets) > 1:
            findings.append(
                ('duplicate_pairing', eid, 'enrollment paired to multiple tickets: %s' % ', '.join(tickets))
            )

    for row in rows:
        if row.get('pair_error'):
            findings.append(('invalid_pairing', row['id'], row['pair_error']))
        state = row.get('state')
        if state in TERMINAL_STATES and row.get('terminal_at') is None and not row.get('pair_error'):
            findings.append(('malformed_terminal_timestamp', row['id'], 'terminal record lacks valid timestamp'))

    status = retention_status(enrollments_dir, bootstrap_dir, retention_days, now=now)
    # Eligible records past retention that were not cleaned indicate a retention problem.
    # Small counts can be transient between cleanup triggers; warn once when overdue.
    if status['eligible'] > 0:
        findings.append((
            'retention_overdue',
            'summary',
            'terminal records eligible for cleanup remain: %s (retention=%s days)'
            % (status['eligible'], retention_days),
        ))

    return findings, status
