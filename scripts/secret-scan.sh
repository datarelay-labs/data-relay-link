#!/usr/bin/env bash
# Fail if tracked files look like runtime secrets, private keys, or
# deployment-specific literals that must not ship in this public repository.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "SECRET_SCAN=FAIL $1" >&2; exit 1; }

if git grep -nE 'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY' -- . >/dev/null; then
  fail "private key material is tracked"
fi

# Runtime artifacts must never be committed.
while IFS= read -r path; do
  case "$path" in
    */server_token|*/install_key|*/registry.json|*/access-info.txt|*/frpc.toml|*/frps.toml|*/client-state.json)
      fail "runtime secret/config is tracked: $path"
      ;;
  esac
done < <(git ls-files)

if git grep -nE 'INSTALL_KEY=' -- ':!tests/' ':!README.md' ':!scripts/secret-scan.sh' >/dev/null; then
  fail "INSTALL_KEY assignment found"
fi

# Known historical production addresses must not re-enter tracked source.
if git grep -nF '221.139.249.110' -- ':!scripts/secret-scan.sh' >/dev/null; then
  fail "forbidden production public IP 221.139.249.110 is tracked"
fi
if git grep -nF '10.39.163.128' -- ':!scripts/secret-scan.sh' >/dev/null; then
  fail "forbidden LXD runtime address 10.39.163.128 is tracked"
fi
if git grep -nF 'RickLee-kr/frp-auto-deploy' -- ':!scripts/secret-scan.sh' >/dev/null; then
  fail "stale repository URL RickLee-kr/frp-auto-deploy is tracked"
fi
if git grep -nF 'raw.githubusercontent.com/RickLee-kr/frp-auto-deploy' -- ':!scripts/secret-scan.sh' >/dev/null; then
  fail "stale raw.githubusercontent.com/RickLee-kr/frp-auto-deploy URL is tracked"
fi
if git grep -nF 'github.com/RickLee-kr/frp-auto-deploy' -- ':!scripts/secret-scan.sh' >/dev/null; then
  fail "stale github.com/RickLee-kr/frp-auto-deploy URL is tracked"
fi
# Former product repository identity (pre datarelay-labs/data-relay-link rename).
# Tests may mention the stale string only when asserting it must be absent.
if git grep -nF 'xdr-labs/frp-auto-deploy' \
  -- ':!scripts/secret-scan.sh' ':!CHANGELOG.md' \
  ':!tests/test-user-facing-branding.sh' ':!tests/test-create-client.sh' \
  ':!tests/test-server-install-config.sh' >/dev/null; then
  fail "stale repository URL xdr-labs/frp-auto-deploy is tracked"
fi
if git grep -nF 'frp.xdr.ooo' \
  -- ':!scripts/secret-scan.sh' ':!CHANGELOG.md' \
  ':!tests/test-user-facing-branding.sh' ':!tests/test-create-client.sh' \
  ':!tests/test-server-install-config.sh' >/dev/null; then
  fail "stale documentation domain frp.xdr.ooo is tracked"
fi

if git grep -nF '192.168.122.' -- '*.md' >/dev/null; then
  fail "libvirt-style 192.168.122.0/24 address in documentation"
fi

echo "SECRET_SCAN=PASS"
