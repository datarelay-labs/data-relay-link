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
# ssh_user is optional connection-example metadata; enrollment does not require it.
got = mod.normalize_service(base)
assert 'ssh_user' not in got, got
print('NEW_SSH_MISSING_USER=OPTIONAL_OK')

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
        raise AssertionError('accepted invalid ssh_user: %r' % (bad,))
print('NEW_SSH_INVALID_USER=REJECTED')
print('SSH_EXPLICIT_USER_TEST=PASS')
PY
