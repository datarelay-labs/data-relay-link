#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('allocator', root / 'server/frp-port-allocator.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

base = {
    'id': 'ssh', 'name': 'SSH', 'protocol': 'tcp', 'preset': 'ssh',
    'local_ip': '127.0.0.1', 'local_port': 22,
}
try:
    mod.normalize_service(base)
except mod.ServiceValidationError as exc:
    assert 'ssh_user is required' in str(exc)
else:
    raise AssertionError('missing ssh_user was accepted')
print('NEW_SSH_MISSING_USER=REJECTED')

item = dict(base, ssh_user='deploy.user')
assert mod.normalize_service(item)['ssh_user'] == 'deploy.user'
print('NEW_SSH_EXPLICIT_USER=PASS')

for guessed in ('root', 'ubuntu', 'admin', 'ec2-user', 'centos'):
    # Explicit values remain valid usernames; they must not be inferred.
    got = mod.normalize_service(dict(base, ssh_user=guessed))['ssh_user']
    assert got == guessed

for bad in ('root\nx', '\x1broot', 'bad user', 'root\x9b'):
    try:
        mod.normalize_service(dict(base, ssh_user=bad))
    except mod.ServiceValidationError:
        pass
    else:
        raise AssertionError('invalid ssh_user was accepted: %r' % bad)
PY

if ! command -v grep >/dev/null 2>&1; then
  echo "FAIL: grep is required for this test" >&2
  exit 1
fi
if grep -nE "ssh_user.*(or 'root'|else 'root'|get\('ssh_user'.*root)|or ['\"]ubuntu['\"]|or ['\"]ec2-user['\"]" \
  "$ROOT/lib/frp-client-common.sh" "$ROOT/server/frp-port-allocator.py" \
  "$ROOT/install-client.sh" "$ROOT/tools/frp-client" >/dev/null; then
  echo "FAIL implicit SSH user fallback remains" >&2
  exit 1
fi
echo "NO_IMPLICIT_ROOT=PASS"

echo "SSH_EXPLICIT_USER_TEST=PASS"
