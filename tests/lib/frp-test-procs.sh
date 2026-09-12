#!/usr/bin/env bash
# Test-only process helpers. Do not source from product scripts.
# Stops PIDs this suite started; never the product allocator.

if [[ -n "${FRP_TEST_PROCS_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
FRP_TEST_PROCS_LOADED=1

frp_test_proc_cmdline() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import sys
from pathlib import Path
pid = sys.argv[1]
p = Path('/proc') / pid / 'cmdline'
try:
    data = p.read_bytes()
except OSError:
    sys.exit(0)
parts = [x.decode('utf-8', 'replace') for x in data.split(b'\0') if x]
print(' '.join(parts))
PY
}

frp_test_proc_config_arg() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import sys
from pathlib import Path
pid = sys.argv[1]
p = Path('/proc') / pid / 'cmdline'
try:
    parts = [x.decode('utf-8', 'replace') for x in p.read_bytes().split(b'\0') if x]
except OSError:
    sys.exit(0)
for i, arg in enumerate(parts):
    if arg == '--config' and i + 1 < len(parts):
        print(parts[i + 1])
        break
    if arg.startswith('--config='):
        print(arg.split('=', 1)[1])
        break
PY
}

frp_test_is_tmp_config() {
  local cfg="$1"
  python3 - "$cfg" <<'PY'
import os, sys
cfg = sys.argv[1]
roots = []
for key in ('TMPDIR', 'TMP', 'TEMP'):
    val = os.environ.get(key)
    if val:
        roots.append(val)
roots.extend(('/tmp', '/var/tmp'))
for root in roots:
    root = os.path.abspath(root)
    path = cfg if cfg.startswith('/') else os.path.abspath(cfg)
    if path == root or path.startswith(root.rstrip('/') + '/'):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

# Alive check must not use kill -0 alone: EPERM on a root product process
# looks like "dead" to an unprivileged test user. Zombies still have /proc
# entries; treat them as not running so wait/reap can finish.
frp_test_pid_alive() {
  local pid="$1" st
  [[ -n "$pid" && -r "/proc/$pid/status" ]] || return 1
  st="$(awk '/^State:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)"
  [[ -n "$st" && "$st" != "Z" ]]
}

frp_test_is_product_allocator() {
  local pid="$1" cfg=""
  [[ -n "$pid" ]] || return 1
  frp_test_pid_alive "$pid" || return 1
  cfg="$(frp_test_proc_config_arg "$pid" || true)"
  [[ -n "$cfg" ]] || return 1
  if frp_test_is_tmp_config "$cfg"; then
    return 1
  fi
  case "$cfg" in
    /etc/drlink/config.json|*/etc/drlink/config.json)
      return 0
      ;;
  esac
  return 1
}

# Stop one PID this test owns. Refuses a live product allocator.
# SIGTERM, wait, SIGKILL, wait. Returns non-zero if the process remains.
frp_test_stop_pid() {
  local pid="${1:-}" i
  [[ -n "$pid" ]] || return 0
  if frp_test_is_product_allocator "$pid"; then
    echo "ERROR: refusing to stop product allocator pid=$pid" >&2
    return 1
  fi
  if ! frp_test_pid_alive "$pid"; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  i=0
  while frp_test_pid_alive "$pid"; do
    if (( i >= 50 )); then
      break
    fi
    sleep 0.1
    i=$((i + 1))
  done
  if frp_test_pid_alive "$pid"; then
    echo "WARN: pid $pid ignored SIGTERM; sending SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
    i=0
    while frp_test_pid_alive "$pid"; do
      if (( i >= 20 )); then
        break
      fi
      sleep 0.1
      i=$((i + 1))
    done
  fi
  wait "$pid" 2>/dev/null || true
  if frp_test_pid_alive "$pid"; then
    echo "ERROR: failed to stop test process pid=$pid cmd=$(frp_test_proc_cmdline "$pid")" >&2
    return 1
  fi
  return 0
}

frp_test_tmp_allocator_pids() {
  python3 - <<'PY'
import os
from pathlib import Path

roots = []
for key in ('TMPDIR', 'TMP', 'TEMP'):
    val = os.environ.get(key)
    if val:
        roots.append(os.path.abspath(val))
roots.extend(['/tmp', '/var/tmp'])

def is_tmp(cfg):
    path = cfg if cfg.startswith('/') else os.path.abspath(cfg)
    for root in roots:
        if path == root or path.startswith(root.rstrip('/') + '/'):
            return True
    return False

pids = []
proc = Path('/proc')
if proc.is_dir():
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            parts = [x.decode('utf-8', 'replace') for x in (entry / 'cmdline').read_bytes().split(b'\0') if x]
        except OSError:
            continue
        joined = ' '.join(parts)
        if 'frp-port-allocator.py' not in joined:
            continue
        cfg = ''
        for i, arg in enumerate(parts):
            if arg == '--config' and i + 1 < len(parts):
                cfg = parts[i + 1]
                break
            if arg.startswith('--config='):
                cfg = arg.split('=', 1)[1]
                break
        if cfg and is_tmp(cfg):
            pids.append(entry.name)
print('\n'.join(pids))
PY
}

frp_test_product_allocator_pids() {
  python3 - <<'PY'
import os
from pathlib import Path

roots = []
for key in ('TMPDIR', 'TMP', 'TEMP'):
    val = os.environ.get(key)
    if val:
        roots.append(os.path.abspath(val))
roots.extend(['/tmp', '/var/tmp'])

def is_tmp(cfg):
    path = cfg if cfg.startswith('/') else os.path.abspath(cfg)
    for root in roots:
        if path == root or path.startswith(root.rstrip('/') + '/'):
            return True
    return False

pids = []
proc = Path('/proc')
if proc.is_dir():
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            parts = [x.decode('utf-8', 'replace') for x in (entry / 'cmdline').read_bytes().split(b'\0') if x]
        except OSError:
            continue
        joined = ' '.join(parts)
        if 'frp-port-allocator.py' not in joined:
            continue
        cfg = ''
        for i, arg in enumerate(parts):
            if arg == '--config' and i + 1 < len(parts):
                cfg = parts[i + 1]
                break
            if arg.startswith('--config='):
                cfg = arg.split('=', 1)[1]
                break
        if cfg and not is_tmp(cfg) and cfg.endswith('/etc/drlink/config.json'):
            pids.append(entry.name)
print('\n'.join(pids))
PY
}

frp_test_assert_no_tmp_allocators() {
  local pids pid cfg
  pids="$(frp_test_tmp_allocator_pids || true)"
  if [[ -z "${pids//[$'\n']/}" ]]; then
    return 0
  fi
  echo "ERROR: leftover test-owned allocator(s):" >&2
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    cfg="$(frp_test_proc_config_arg "$pid" || true)"
    echo "  pid=$pid config=${cfg:-unknown} cmd=$(frp_test_proc_cmdline "$pid")" >&2
  done <<<"$pids"
  return 1
}

frp_test_stop_tmp_allocators() {
  local pids pid rc=0
  pids="$(frp_test_tmp_allocator_pids || true)"
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    frp_test_stop_pid "$pid" || rc=1
  done <<<"$pids"
  return "$rc"
}

# EXIT/INT/TERM/HUP trap body. Uses ALLOC_PID, LISTEN_PID, WORKDIR from caller.
# EXIT must not call `exit` or `trap - EXIT`: a chained product EXIT trap that
# evals this handler will SIGSEGV bash if we exit while that trap is running.
frp_test_trap_cleanup() {
  local mode="${1:-}"
  local rc="${FRP_SAVED_EXIT_RC:-$?}"
  unset FRP_SAVED_EXIT_RC || true
  if [[ "$mode" == signal ]]; then
    trap - EXIT INT TERM HUP
  fi
  set +e
  local stop_rc=0
  if [[ -n "${ALLOC_PID:-}" ]]; then
    frp_test_stop_pid "$ALLOC_PID"
    stop_rc=$?
    ALLOC_PID=""
  fi
  if [[ -n "${LISTEN_PID:-}" ]]; then
    frp_test_stop_pid "$LISTEN_PID" || stop_rc=1
    LISTEN_PID=""
  fi
  if [[ -n "${WORKDIR:-}" ]]; then
    rm -rf "$WORKDIR" || stop_rc=1
  fi
  if (( stop_rc != 0 )); then
    echo "FAIL test-owned process cleanup" >&2
    if (( rc == 0 )); then
      rc=1
    fi
  fi
  if [[ "$mode" == signal ]]; then
    exit "$rc"
  fi
  return 0
}

frp_test_arm_cleanup() {
  trap frp_test_trap_cleanup EXIT
  trap 'FRP_SAVED_EXIT_RC=130; frp_test_trap_cleanup signal' INT
  trap 'FRP_SAVED_EXIT_RC=143; frp_test_trap_cleanup signal' TERM
  trap 'FRP_SAVED_EXIT_RC=129; frp_test_trap_cleanup signal' HUP
}
