#!/usr/bin/env bash
# Shared client-side helpers for install-client.sh and tools/frp-client.
# Source this file; do not execute it.

if [[ -n "${FRP_CLIENT_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
FRP_CLIENT_COMMON_LOADED=1

FRP_CLIENT_STATE_SCHEMA=1
FRP_CLIENT_BACKUP_KEEP="${FRP_CLIENT_BACKUP_KEEP:-5}"
FRP_CLIENT_UPGRADE_BACKUP_KEEP="${FRP_CLIENT_UPGRADE_BACKUP_KEEP:-5}"

# Defaults match VERSION. A sibling VERSION file overrides project/FRP versions.
PROJECT_VERSION="${PROJECT_VERSION:-2.1.3}"
FRP_VERSION="${FRP_VERSION:-0.70.1}"
_FRP_CLIENT_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_FRP_CLIENT_COMMON_DIR}/../VERSION" ]]; then
  # shellcheck disable=SC1091
  . "${_FRP_CLIENT_COMMON_DIR}/../VERSION"
fi
if [[ -z "${FRP_COMMON_LOADED:-}" ]]; then
  if [[ -f "${_FRP_CLIENT_COMMON_DIR}/frp-common.sh" ]]; then
    # shellcheck source=frp-common.sh
    . "${_FRP_CLIENT_COMMON_DIR}/frp-common.sh"
  elif [[ -f /usr/local/lib/frp-auto-deploy/frp-common.sh ]]; then
    # shellcheck disable=SC1091
    . /usr/local/lib/frp-auto-deploy/frp-common.sh
  elif [[ -f '/Library/Application Support/frp-auto-deploy/lib/frp-common.sh' ]]; then
    # shellcheck disable=SC1091
    . '/Library/Application Support/frp-auto-deploy/lib/frp-common.sh'
  fi
fi
if [[ -z "${FRP_CLIENT_UPDATE_URL:-}" ]]; then
  FRP_CLIENT_UPDATE_URL="$(frp_default_client_update_url)"
fi
if [[ -z "${FRP_CLIENT_UPDATE_METADATA_URL:-}" ]]; then
  FRP_CLIENT_UPDATE_METADATA_URL="$(frp_default_client_update_metadata_url)"
fi

frp_client_path() {
  local p="$1"
  # frp-common.sh may be absent in older staged test fixtures; keep Linux identity.
  if declare -F frp_platform_map_path >/dev/null 2>&1; then
    p="$(frp_platform_map_path "$p")"
  fi
  if [[ -n "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    printf '%s' "${FRP_CLIENT_TEST_ROOT}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_client_state_path() {
  frp_client_path /etc/frp/client-state.json
}

frp_client_toml_path() {
  frp_client_path /etc/frp/frpc.toml
}

frp_client_access_path() {
  frp_client_path /etc/frp/access-info.txt
}

frp_client_backup_dir() {
  frp_client_path /etc/frp/backups
}

frp_client_lock_dir() {
  frp_client_path /etc/frp/client-manage.lock
}

frp_client_pending_path() {
  frp_client_path /etc/frp/apply-pending.json
}

frp_client_identity_key_path() {
  frp_client_path /etc/frp/client-identity.key
}

frp_client_identity_pub_path() {
  frp_client_path /etc/frp/client-identity.pub
}

frp_client_identity_mac_path() {
  frp_client_path /etc/frp/client-identity.mac
}

frp_pending_enroll_path() {
  frp_client_path /etc/frp/enroll-pending.json
}

frp_allocator_ca_path() {
  frp_client_path /etc/frp-auto-deploy/allocator-ca.crt
}

frp_valid_https_allocator_url() {
  local url="${1:-}"
  case "$url" in
    https://?*) ;;
    *) return 1 ;;
  esac
  if [[ "$url" == *$'\n'* || "$url" == *$'\r'* || "$url" == *$'\t'* || "$url" == *' '* ]]; then
    return 1
  fi
  local rest="${url#https://}"
  local hostport="${rest%%/*}"
  [[ -n "$hostport" ]]
}

frp_allocator_origin_url() {
  local url="${1:-}"
  python3 - "$url" <<'PY'
import sys
url = sys.argv[1].strip()
if not url.lower().startswith('https://'):
    raise SystemExit(1)
rest = url[8:]
hostport = rest.split('/', 1)[0]
if not hostport:
    raise SystemExit(1)
sys.stdout.write('https://' + hostport)
PY
}

frp_ca_validate_x509() {
  local src="$1"
  local err="${2:-allocator CA is not a valid X.509 certificate}"
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required to validate the allocator CA" >&2
    return 1
  fi
  if ! openssl x509 -in "$src" -noout >/dev/null 2>&1; then
    echo "ERROR: ${err}" >&2
    return 1
  fi
  return 0
}

frp_ca_fingerprint_file() {
  local src="$1" der fp
  local err="${2:-allocator CA is not a valid X.509 certificate}"
  frp_ca_validate_x509 "$src" "$err" || return 1
  der="$(mktemp)"
  if ! openssl x509 -in "$src" -outform DER -out "$der" 2>/dev/null || [[ ! -s "$der" ]]; then
    rm -f "$der"
    echo "ERROR: ${err}" >&2
    return 1
  fi
  fp="$(python3 - "$der" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)" || {
    rm -f "$der"
    echo "ERROR: ${err}" >&2
    return 1
  }
  rm -f "$der"
  if [[ ! "$fp" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: ${err}" >&2
    return 1
  fi
  printf '%s\n' "$fp"
}

frp_normalize_ca_fingerprint() {
  python3 - "$1" <<'PY'
import re, sys
text = sys.argv[1]
cleaned = []
for ch in text:
    o = ord(ch)
    if 48 <= o <= 57:
        cleaned.append(ch)
    elif 65 <= o <= 70:
        cleaned.append(chr(o + 32))
    elif 97 <= o <= 102:
        cleaned.append(ch)
hexstr = ''.join(cleaned)
if not re.fullmatch(r'[0-9a-f]{64}', hexstr):
    raise SystemExit(1)
print(hexstr)
PY
}

frp_atomic_install_allocator_ca() {
  local src="$1" dest expected actual tmp dir
  dest="$(frp_allocator_ca_path)"
  expected="${2:-}"
  actual="$(frp_ca_fingerprint_file "$src")" || return 1
  if [[ -n "$expected" ]]; then
    expected="$(frp_normalize_ca_fingerprint "$expected")" || {
      echo "ERROR: invalid CA fingerprint" >&2
      return 1
    }
    if [[ "$actual" != "$expected" ]]; then
      echo "ERROR: CA fingerprint mismatch" >&2
      return 1
    fi
  fi
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/allocator-ca.crt.XXXXXX")"
  cp "$src" "$tmp"
  chmod 644 "$tmp"
  if [[ "$(id -u)" == "0" ]]; then
    chown root:root "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
  chmod 644 "$dest"
}

frp_bootstrap_allocator_ca() {
  local url="${1:-}" origin ca_url dest tmp expected actual
  dest="$(frp_allocator_ca_path)"
  expected="${FRP_ALLOCATOR_CA_SHA256:-}"

  if ! frp_valid_https_allocator_url "$url"; then
    if [[ "$url" == http://* ]]; then
      echo "ERROR: plain HTTP allocator URL is not supported; HTTPS is required" >&2
    else
      echo "ERROR: FRP allocator URL must be an https:// URL with a host" >&2
    fi
    return 1
  fi

  if [[ -n "${FRP_ALLOCATOR_CA_FILE:-}" ]]; then
    [[ -f "$FRP_ALLOCATOR_CA_FILE" ]] || {
      echo "ERROR: pre-provisioned allocator CA file is missing" >&2
      return 1
    }
    frp_atomic_install_allocator_ca "$FRP_ALLOCATOR_CA_FILE" "$expected" || return 1
    return 0
  fi

  if [[ -f "$dest" ]]; then
    actual="$(frp_ca_fingerprint_file "$dest")" || return 1
    if [[ -n "$expected" ]]; then
      expected="$(frp_normalize_ca_fingerprint "$expected")" || {
        echo "ERROR: invalid CA fingerprint" >&2
        return 1
      }
      if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: CA fingerprint mismatch" >&2
        return 1
      fi
    fi
    return 0
  fi

  if [[ -z "$expected" ]]; then
    echo "ERROR: allocator CA SHA256 fingerprint is required for first enrollment" >&2
    echo "Set FRP_ALLOCATOR_CA_SHA256 from frp-create-client, or supply FRP_ALLOCATOR_CA_FILE." >&2
    return 1
  fi
  expected="$(frp_normalize_ca_fingerprint "$expected")" || {
    echo "ERROR: invalid CA fingerprint" >&2
    return 1
  }

  origin="$(frp_allocator_origin_url "$url")" || {
    echo "ERROR: cannot derive allocator origin from URL" >&2
    return 1
  }
  ca_url="${origin}/ca.crt"
  tmp="$(mktemp)"
  # Insecure retrieval is limited to the public CA certificate. No code,
  # identity, or management headers are sent on this request.
  if ! curl --fail --silent --show-error --max-time 30 \
    --proto '=https' --insecure \
    -o "$tmp" \
    "$ca_url"; then
    rm -f "$tmp"
    echo "ERROR: allocator TLS CA certificate could not be downloaded from ${ca_url}" >&2
    return 1
  fi
  if ! frp_ca_validate_x509 "$tmp" "downloaded allocator CA is not a valid X.509 certificate"; then
    rm -f "$tmp"
    return 1
  fi
  if ! actual="$(frp_ca_fingerprint_file "$tmp" "downloaded allocator CA is not a valid X.509 certificate")"; then
    rm -f "$tmp"
    return 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    rm -f "$tmp"
    echo "ERROR: CA fingerprint mismatch" >&2
    return 1
  fi
  if ! frp_atomic_install_allocator_ca "$tmp" "$expected"; then
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  return 0
}

frp_explain_allocator_curl_error() {
  local err_file="${1:-}"
  local text=""
  if [[ -n "$err_file" && -f "$err_file" ]]; then
    text="$(cat "$err_file" 2>/dev/null || true)"
  fi
  local lowered
  lowered="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lowered" == *'could not get local issuer'* || "$lowered" == *'unable to get local issuer'* || "$lowered" == *'unknown ca'* ]]; then
    echo "ERROR: allocator TLS verification failed: unknown CA" >&2
  elif [[ "$lowered" == *'does not match'* || "$lowered" == *'alternative certificate subject'* || "$lowered" == *'hostname'* ]]; then
    echo "ERROR: allocator TLS verification failed: server certificate hostname mismatch" >&2
  elif [[ "$lowered" == *'expired'* ]]; then
    echo "ERROR: allocator TLS verification failed: expired certificate" >&2
  elif [[ "$lowered" == *'not yet valid'* ]]; then
    echo "ERROR: allocator TLS verification failed: certificate is not yet valid" >&2
  elif [[ "$lowered" == *'connection refused'* || "$lowered" == *'failed to connect'* ]]; then
    echo "ERROR: allocator TLS listener unavailable" >&2
  else
    echo "ERROR: allocator request failed" >&2
  fi
  if [[ -n "$text" ]]; then
    printf '%s\n' "$text" >&2
  fi
}

frp_allocator_curl() {
  local ca dest
  dest="$(frp_allocator_ca_path)"
  if [[ ! -f "$dest" ]]; then
    echo "ERROR: trusted allocator CA is missing (${dest})" >&2
    echo "ERROR: unknown CA; re-run enrollment with FRP_ALLOCATOR_CA_SHA256" >&2
    return 1
  fi
  curl --silent --show-error --cacert "$dest" "$@"
}

frp_mgmt_auth_py() {
  local cand libdir here
  if [[ -n "${FRP_MGMT_AUTH_PY:-}" && -f "${FRP_MGMT_AUTH_PY}" ]]; then
    printf '%s' "$FRP_MGMT_AUTH_PY"
    return 0
  fi
  libdir="$(frp_client_lib_dir)"
  for cand in \
    "${libdir}/frp_mgmt_auth.py" \
    "${FRP_CLIENT_LIB:-}/frp_mgmt_auth.py"
  do
    if [[ -f "$cand" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  done
  if [[ -n "${FRP_CLIENT_LIB:-}" && -f "${FRP_CLIENT_LIB}" ]]; then
    cand="$(dirname "$FRP_CLIENT_LIB")/frp_mgmt_auth.py"
    if [[ -f "$cand" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  fi
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for cand in \
    "$here/frp_mgmt_auth.py" \
    "$here/../lib/frp_mgmt_auth.py" \
    /usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py
  do
    if [[ -f "$cand" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  done
  echo "ERROR: missing frp_mgmt_auth.py" >&2
  return 1
}

frp_identity_status() {
  local key pub mac macval
  key="$(frp_client_identity_key_path)"
  pub="$(frp_client_identity_pub_path)"
  mac="$(frp_client_identity_mac_path)"
  if [[ ! -e "$key" && ! -e "$pub" && ! -e "$mac" ]]; then
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$key" ]]; then
    printf 'corrupt'
    return 0
  fi
  if ! python3 "$(frp_mgmt_auth_py)" check-key "$key" >/dev/null 2>&1; then
    printf 'corrupt'
    return 0
  fi
  # A local key without a confirmed response key is not enrolled. This avoids
  # treating a half-finished first enrollment as a usable identity.
  if [[ ! -f "$mac" ]]; then
    printf 'pending'
    return 0
  fi
  macval="$(tr -d '\n' <"$mac" 2>/dev/null || true)"
  if [[ ${#macval} -ne 64 ]]; then
    printf 'pending'
    return 0
  fi
  printf 'enrolled'
}

frp_identity_label() {
  case "$(frp_identity_status)" in
    enrolled) printf 'enrolled' ;;
    corrupt) printf 'unusable' ;;
    *) printf 'not established' ;;
  esac
}

frp_identity_ensure() {
  local key pub status py
  key="$(frp_client_identity_key_path)"
  pub="$(frp_client_identity_pub_path)"
  py="$(frp_mgmt_auth_py)" || return 1
  mkdir -p "$(dirname "$key")"
  chmod 700 "$(dirname "$key")" 2>/dev/null || true
  status="$(frp_identity_status)"
  if [[ "$status" == corrupt ]]; then
    echo "ERROR: this client's management identity is unusable." >&2
    echo "The local identity file exists but cannot be used." >&2
    echo "Create a new Enrollment Code on the FRP server with sudo frp-create-client," >&2
    echo "move the damaged identity aside, then re-enroll this client." >&2
    echo "Do not overwrite ${key} automatically." >&2
    return 1
  fi
  if [[ "$status" == enrolled || "$status" == pending ]]; then
    if [[ ! -f "$pub" ]]; then
      python3 "$py" pub "$key" >"${pub}.tmp"
      chmod 644 "${pub}.tmp"
      mv "${pub}.tmp" "$pub"
    fi
    return 0
  fi
  python3 "$py" gen-key "$key" "$pub"
  chmod 600 "$key"
  chmod 644 "$pub" 2>/dev/null || true
}

frp_identity_public_pem() {
  local key pub py
  py="$(frp_mgmt_auth_py)" || return 1
  key="$(frp_client_identity_key_path)"
  pub="$(frp_client_identity_pub_path)"
  if [[ -f "$pub" ]]; then
    python3 "$py" pub "$key"
    return 0
  fi
  python3 "$py" pub "$key"
}

frp_identity_store_mac() {
  local dest value="${1:-}"
  dest="$(frp_client_identity_mac_path)"
  MGMT_MAC_VALUE="$value" python3 - "$dest" <<'PY'
import os, sys, tempfile
from pathlib import Path
dest = Path(sys.argv[1])
text = os.environ.get('MGMT_MAC_VALUE', '').strip() + '\n'
if len(text.strip()) != 64:
    raise SystemExit('ERROR: invalid management response key')
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
  unset MGMT_MAC_VALUE
}

frp_identity_load_mac() {
  local path
  path="$(frp_client_identity_mac_path)"
  if [[ ! -f "$path" ]]; then
    echo "ERROR: management identity is missing a response key; re-enroll this client." >&2
    return 1
  fi
  tr -d '\n' <"$path"
}

frp_identity_derive_and_store_mac() {
  local machine_id="$1" secret="$2" mac py
  py="$(frp_mgmt_auth_py)" || return 1
  mac="$(MGMT_ENROLL_SECRET="$secret" python3 "$py" derive-mac "$machine_id")" || return 1
  unset MGMT_ENROLL_SECRET
  if [[ ${#mac} -ne 64 ]]; then
    echo "ERROR: failed to derive management response key" >&2
    return 1
  fi
  frp_identity_store_mac "$mac"
}

frp_identity_public_fingerprint() {
  # SHA-256 fingerprint (hex) of this client's management public key, when a
  # local identity exists. Used only for crash-safe recovery bookkeeping
  # (lib/frp-client-common.sh pending-enrollment helpers); never required for
  # trust decisions, which remain signature-based.
  local pub py
  pub="$(frp_client_identity_pub_path)"
  [[ -f "$pub" ]] || return 1
  py="$(frp_mgmt_auth_py)" || return 1
  python3 "$py" fingerprint "$pub" 2>/dev/null | tr -d '\n'
}

frp_read_existing_token() {
  python3 - "$(frp_client_toml_path)" <<'PY'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit('ERROR: existing FRP client configuration is missing; re-enroll this client.')
text = path.read_text(encoding='utf-8')
for line in text.splitlines():
    m = re.match(r'^\s*auth\.token\s*=\s*"(.*)"\s*$', line)
    if m:
        sys.stdout.write(m.group(1))
        raise SystemExit(0)
raise SystemExit('ERROR: existing FRP client configuration is missing the FRP token; re-enroll this client.')
PY
}

frp_client_lib_dir() {
  frp_client_path /usr/local/lib/frp-auto-deploy
}

frp_client_version_file() {
  frp_client_path /etc/frp-auto-deploy/version
}

frp_client_upgrade_backup_root() {
  frp_client_path /var/lib/frp-auto-deploy/client-upgrades
}

frp_client_write_version_file() {
  frp_write_version_file "$(frp_client_version_file)" client
}

frp_client_read_kv() {
  local file="$1" key="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  awk -F= -v k="$key" '$1==k {print substr($0, index($0,"=")+1); exit}' "$file"
}

frp_client_installed_project_version() {
  local pv
  pv="$(frp_client_read_kv "$(frp_client_version_file)" PROJECT_VERSION)"
  if [[ -z "$pv" ]]; then
    printf '%s' "legacy / unknown"
    return 0
  fi
  printf '%s' "$pv"
}

frp_client_installed_frp_version() {
  local fv
  fv="$(frp_client_read_kv "$(frp_client_version_file)" FRP_VERSION)"
  if [[ -n "$fv" ]]; then
    printf '%s' "$fv"
    return 0
  fi
  printf '%s' "${FRP_VERSION:-0.70.1}"
}

frp_client_installed_release_channel() {
  local v
  v="$(frp_client_read_kv "$(frp_client_version_file)" RELEASE_CHANNEL)"
  if [[ -z "$v" ]]; then
    printf '%s' "unknown"
    return 0
  fi
  printf '%s' "$v"
}

frp_client_installed_source_ref() {
  local v
  v="$(frp_client_read_kv "$(frp_client_version_file)" SOURCE_REF)"
  if [[ -z "$v" ]]; then
    printf '%s' "unknown"
    return 0
  fi
  printf '%s' "$v"
}

frp_client_installed_bundle_sha256() {
  local v
  v="$(frp_client_read_kv "$(frp_client_version_file)" BUNDLE_SHA256)"
  if [[ -z "$v" ]]; then
    printf '%s' "unknown"
    return 0
  fi
  printf '%s' "$v"
}

frp_client_external_bundle_sha256() {
  # Artifact SHA passed in from an external verifier (SHA256SUMS), not a
  # self-hash of the bundle that is about to execute.
  local digest=""
  if [[ "${FRP_BUNDLE_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    digest="$(printf '%s' "$FRP_BUNDLE_SHA256" | tr '[:upper:]' '[:lower:]')"
  elif [[ "${FRP_VERIFIED_CLIENT_UPDATE_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    digest="$(printf '%s' "$FRP_VERIFIED_CLIENT_UPDATE_SHA256" | tr '[:upper:]' '[:lower:]')"
  elif [[ "${FRP_CLIENT_UPDATE_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    digest="$(printf '%s' "$FRP_CLIENT_UPDATE_SHA256" | tr '[:upper:]' '[:lower:]')"
  fi
  printf '%s' "$digest"
}

frp_client_known_release_channel() {
  local raw="${1:-}" parsed=""
  parsed="$(frp_parse_known_release_channel "$raw" 2>/dev/null)" || return 1
  [[ -n "$parsed" ]] || return 1
  printf '%s' "$parsed"
}

frp_client_has_trustworthy_release_line() {
  local channel ref
  channel="$(frp_client_installed_release_channel)"
  ref="$(frp_client_installed_source_ref)"
  frp_client_known_release_channel "$channel" >/dev/null || return 1
  [[ -n "$ref" && "$ref" != "unknown" ]] || return 1
  return 0
}

frp_client_has_verified_build_identity() {
  local sha
  sha="$(frp_client_installed_bundle_sha256)"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]]
}

frp_client_explicit_expected_channel() {
  local raw="${FRP_EXPECTED_RELEASE_CHANNEL:-${FRP_RELEASE_CHANNEL:-}}"
  [[ -n "$raw" ]] || return 1
  frp_client_known_release_channel "$raw"
}

frp_client_emit_legacy_secure_bridge() {
  echo "ERROR: this client has no trustworthy persisted release identity." >&2
  echo "A pre-P2.20 updater cannot retroactively verify an artifact before executing it." >&2
  echo "A bundle hashing itself is identity, not external verification." >&2
  echo "Perform the documented one-time verified bridge; do not pipe main into sudo." >&2
  echo "Legacy secure bridge required"
  echo "State mutation           : NO"
  frp_emit_failure_class LEGACY_CLIENT_SECURE_BRIDGE_REQUIRED
}

frp_client_report_identity() {
  local installed_version="$1" target_version="$2"
  local installed_channel="$3" target_channel="$4"
  local installed_ref="$5" target_ref="$6"
  local installed_bundle="$7" target_bundle="$8"
  echo "Installed project version : ${installed_version}"
  echo "Target project version    : ${target_version}"
  echo "Installed release channel : ${installed_channel}"
  echo "Target release channel    : ${target_channel}"
  echo "Installed source ref      : ${installed_ref}"
  echo "Target source ref         : ${target_ref}"
  echo "Installed bundle SHA256   : ${installed_bundle}"
  echo "Target bundle SHA256      : ${target_bundle}"
}

frp_client_has_existing_install() {
  if [[ -f "$(frp_client_state_path)" ]]; then
    return 0
  fi
  if [[ -f "$(frp_client_toml_path)" && -f "$(frp_client_identity_key_path)" ]]; then
    return 0
  fi
  return 1
}

frp_client_has_partial_install() {
  if frp_client_has_existing_install; then
    return 1
  fi
  if [[ -f "$(frp_client_path /etc/systemd/system/frpc.service)" ]]; then
    return 0
  fi
  return 1
}

frp_client_hook_log() {
  if [[ -n "${FRP_CLIENT_HOOK_LOG:-}" ]]; then
    printf '%s\n' "$1" >>"$FRP_CLIENT_HOOK_LOG"
  fi
}

frp_client_test_hook() {
  local name="$1"
  local var="FRP_CLIENT_HOOK_${name}"
  frp_client_hook_log "$name"
  if [[ -n "${FRP_CLIENT_TEST_ROOT:-}" && "${!var:-}" == "1" ]]; then
    echo "ERROR: simulated ${name} failure" >&2
    return 1
  fi
  return 0
}

if ! declare -F frp_emit_failure_class >/dev/null 2>&1; then
  frp_emit_failure_class() {
    local class="$1"
    printf 'FAILURE_CLASS=%s\n' "$class"
    printf 'FAILURE_CLASS=%s\n' "$class" >&2
  }
fi

_FRP_TEST_INPUT_READY=0

frp_test_input_path() {
  printf '%s' "${FRP_CLIENT_TEST_INPUT_FILE:-${TMPDIR:-/tmp}/frp-client-test-input.$$}"
}

frp_reset_test_input() {
  _FRP_TEST_INPUT_READY=0
  rm -f "$(frp_test_input_path)"
}

frp_using_test_input() {
  [[ -n "${FRP_CLIENT_TEST_INPUT+x}" ]]
}

frp_open_test_input() {
  local file
  file="$(frp_test_input_path)"
  if [[ -f "$file" ]]; then
    return 0
  fi
  printf '%s' "${FRP_CLIENT_TEST_INPUT}" >"$file"
  if [[ -n "${FRP_CLIENT_TEST_INPUT:-}" && "${FRP_CLIENT_TEST_INPUT}" != *$'\n' ]]; then
    printf '\n' >>"$file"
  fi
}

frp_read_test_line() {
  local file first
  frp_open_test_input
  file="$(frp_test_input_path)"
  first="$(python3 - "$file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8') if path.is_file() else ''
if not text:
    sys.stdout.write('')
    raise SystemExit(0)
if text.endswith('\n') and text.count('\n') == 1 and text[:-1] == '':
    first, rest = '', ''
elif '\n' in text:
    first, rest = text.split('\n', 1)
else:
    first, rest = text, ''
path.write_text(rest, encoding='utf-8')
sys.stdout.write(first)
PY
)"
  printf '%s' "$first"
}

prompt_secret() {
  local prompt="$1" var="$2"
  if [[ -n "${!var:-}" ]]; then return 0; fi
  if frp_using_test_input; then
    printf '%s\n' "$prompt" >&2
    printf -v "$var" '%s' "$(frp_read_test_line)"
    return 0
  fi
  if [[ -r /dev/tty ]]; then
    read -r -s -p "$prompt" "$var" </dev/tty
    echo >/dev/tty
  else
    echo "ERROR: no TTY and $var is not set" >&2
    exit 1
  fi
}

read_tty() {
  local prompt="$1" default="${2:-}"
  local value=""
  if frp_using_test_input; then
    printf '%s\n' "$prompt" >&2
    value="$(frp_read_test_line)"
    printf '%s' "${value:-$default}"
    return 0
  fi
  if [[ -r /dev/tty ]]; then
    read -r -p "$prompt" value </dev/tty || true
  else
    echo "ERROR: no TTY for interactive setup; set FRP_SERVICES_JSON or FRP_CLIENT_TEST_INPUT" >&2
    exit 1
  fi
  printf '%s' "${value:-$default}"
}

probe_tcp() {
  local host="$1" port="$2"
  # Host and port are argv, never interpolated into a shell command string.
  python3 - "$host" "$port" <<'PY'
import socket
import sys

host = sys.argv[1]
port_text = sys.argv[2]
try:
    port = int(port_text)
except (TypeError, ValueError):
    raise SystemExit(1)
if port < 1 or port > 65535:
    raise SystemExit(1)
if not host or any(ch in host for ch in "\r\n\x00"):
    raise SystemExit(1)
try:
    sock = socket.create_connection((host, port), timeout=3)
except Exception:
    raise SystemExit(1)
try:
    sock.close()
except Exception:
    pass
raise SystemExit(0)
PY
}

maybe_warn_connectivity() {
  local host="$1" port="$2" label="$3"
  if [[ "${FRP_SKIP_CONNECTIVITY_CHECK:-}" == "1" ]]; then
    return 0
  fi
  if probe_tcp "$host" "$port"; then
    return 0
  fi
  echo "WARNING: cannot connect to ${label} ${host}:${port} (continuing; target may be remote or not yet listening)"
}

frp_confirm_yes() {
  local prompt="${1:-Continue? [Y/n]: }"
  local answer
  answer="$(read_tty "$prompt" "Y")"
  case "$answer" in
    ''|Y|y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

frp_preset_type_label() {
  case "$1" in
    ssh) printf 'SSH / TCP' ;;
    http) printf 'HTTP / TCP' ;;
    https) printf 'HTTPS / TCP' ;;
    *) printf 'Custom TCP' ;;
  esac
}

service_payload() {
  python3 - "$@" <<'PY'
import json, sys
preset = sys.argv[1]
sid = sys.argv[2]
name = sys.argv[3]
host = sys.argv[4]
port = sys.argv[5]
payload = {
  'id': sid,
  'name': name,
  'protocol': 'tcp',
  'local_ip': host,
  'local_port': port,
  'preset': preset,
}
if preset == 'ssh':
    if len(sys.argv) <= 6 or not sys.argv[6].strip():
        raise SystemExit('ERROR: ssh_user is required for ssh services')
    payload['ssh_user'] = sys.argv[6].strip()
print(json.dumps(payload))
PY
}

frp_ux_intro() {
  cat <<'EOF'

=========================================
 FRP Client Setup
=========================================

This installer publishes services on this Linux system
through your FRP server.

Before continuing, you need an Enrollment Code.

Generate one on the FRP server with:

  sudo frp-create-client

The Enrollment Code is short-lived. Enter it only here.
It authorizes this first enrollment (or a later recovery).
It is not stored on this client and it is not the FRP token.
After enrollment, this client uses a local management identity
for ordinary configuration changes.

Tip:
  Values shown in [brackets] are defaults.
  Press Enter to accept the default value.

EOF
}

frp_ux_enrollment_help() {
  cat <<'EOF'
Enrollment Code
  Generated on the FRP server with: sudo frp-create-client
  Short-lived bootstrap/recovery credential. Entered interactively.
  Not stored. Not the FRP token.
  Needed for first enrollment, recovering a lost local identity,
  or after an administrator revokes this client's management access.
  Ordinary later changes use this client's local management identity.

EOF
}

frp_ux_defaults_help() {
  cat <<'EOF'
Tip:
  Values shown in [brackets] are defaults.
  Press Enter to accept the default value.

EOF
}

frp_ux_service_id_help() {
  local default="${1:-}"
  cat <<EOF
Service ID
  A short unique name for this service.
  Service IDs are lowercase and case-insensitive.
  SSH, ssh, and Ssh are the same ID.

  The Service ID is used together with this machine's identity
  to keep the same public port after reinstall or later changes.

  Usually you can keep the default.

  Examples:
    ssh
    grafana
    admin-web
    api
EOF
  if [[ -n "$default" ]]; then
    echo
  fi
}

frp_ux_target_host_help() {
  cat <<'EOF'
Target host
  The IP address or hostname where the actual service runs.

  Use 127.0.0.1 if the service is running on this machine.
  Enter another reachable internal IP if it runs on another server.

  Examples:
    127.0.0.1
    192.168.10.20
    internal-api.example.local

EOF
}

frp_ux_target_port_help() {
  local preset="${1:-custom}"
  case "$preset" in
    ssh)
      cat <<'EOF'
Target port
  TCP port used by the SSH service on the target host.

  Standard SSH uses port 22.
  Press Enter if this is a normal SSH installation.

EOF
      ;;
    http)
      cat <<'EOF'
Target port
  TCP port used by the web application.

  Standard HTTP uses port 80.
  Examples of alternate ports: 8080, 3000.

EOF
      ;;
    https)
      cat <<'EOF'
Target port
  TCP port used by the HTTPS application.

  Standard HTTPS uses port 443.

EOF
      ;;
    *)
      cat <<'EOF'
Target port
  TCP port used by the application on the target host.

  Examples:
    Grafana      3000
    API          8080
    PostgreSQL   5432

EOF
      ;;
  esac
}

frp_ux_ssh_user_help() {
  cat <<'EOF'
SSH user
  Linux username shown in the generated SSH command.

  This does NOT create an operating-system account,
  change a password, or configure SSH authentication.

EOF
}

frp_ux_add_service_menu() {
  cat <<'EOF'
Add a service
=============

Select the type of service you want to publish.

1) SSH
   Remote shell access.
   Default target: 127.0.0.1:22

2) HTTP
   Web application using plain HTTP.
   Default target: 127.0.0.1:80

3) HTTPS
   Web application using HTTPS.
   Default target: 127.0.0.1:443
   FRP forwards the TCP connection without terminating TLS.

4) Custom TCP
   Any other TCP service.
   Examples: Grafana :3000, API :8080, PostgreSQL :5432

5) Back

For normal remote SSH access, choose 1.

You may publish one or more services.
SSH is optional.

EOF
}

frp_ux_empty_services_help() {
  cat <<'EOF'
No services have been configured yet.

Choose "Add service" to select what you want to access
through the FRP server.

Examples:
  SSH        - remote shell access
  HTTP       - web application using HTTP
  HTTPS      - web application using HTTPS
  Custom TCP - any other TCP service such as Grafana,
               APIs, databases, or appliance management ports

You may publish one or more services.
SSH is optional.

EOF
}

frp_ux_configured_services_help() {
  cat <<'EOF'
The public port will be assigned automatically by the FRP server.

You can add more services now, or install when finished.

You may publish one or more services.
SSH is optional.

EOF
}

frp_ux_print_all_guidance() {
  frp_ux_intro
  frp_ux_enrollment_help
  frp_ux_defaults_help
  frp_ux_service_id_help ssh
  echo
  frp_ux_target_host_help
  frp_ux_target_port_help ssh
  frp_ux_target_port_help http
  frp_ux_target_port_help https
  frp_ux_target_port_help custom
  frp_ux_ssh_user_help
  frp_ux_add_service_menu
  frp_ux_empty_services_help
  frp_ux_configured_services_help
}

frp_prompt_service_id() {
  local default="$1"
  local -n _frp_sid_out="$2"
  frp_ux_service_id_help "$default"
  echo
  _frp_sid_out="$(read_tty "Service ID [${default}]: " "$default")"
}

frp_prompt_target_host() {
  local default="${1:-127.0.0.1}"
  local -n _frp_host_out="$2"
  frp_ux_target_host_help
  _frp_host_out="$(read_tty "Target host [${default}]: " "$default")"
}

frp_prompt_target_port() {
  local preset="$1" default="${2:-}"
  local -n _frp_port_out="$3"
  frp_ux_target_port_help "$preset"
  if [[ -n "$default" ]]; then
    _frp_port_out="$(read_tty "Target port [${default}]: " "$default")"
  else
    _frp_port_out="$(read_tty "Target port: " "")"
  fi
}

frp_prompt_ssh_user() {
  local -n _frp_user_out="$1"
  local default="${2:-${FRP_SSH_USER:-}}"
  _frp_user_out=""
  frp_ux_ssh_user_help
  while [[ -z "$_frp_user_out" ]]; do
    if [[ -n "$default" ]]; then
      _frp_user_out="$(read_tty "SSH user [${default}]: " "$default")"
    else
      _frp_user_out="$(read_tty "SSH user (required): ")"
    fi
    [[ -n "$_frp_user_out" ]] || echo "ERROR: SSH user is required." >&2
  done
}

frp_ux_prompt_new_service() {
  local dest="${1:-}"
  local choice sid host port user name _frp_new_payload
  while true; do
    echo
    frp_ux_add_service_menu
    choice="$(read_tty "Select: " "")"
    case "$choice" in
      1)
        frp_prompt_service_id ssh sid
        frp_prompt_target_host 127.0.0.1 host
        frp_prompt_target_port ssh 22 port
        frp_prompt_ssh_user user
        maybe_warn_connectivity "$host" "$port" "SSH"
        _frp_new_payload="$(service_payload ssh "$sid" SSH "$host" "$port" "$user")"
        ;;
      2)
        frp_prompt_service_id http sid
        frp_prompt_target_host 127.0.0.1 host
        frp_prompt_target_port http 80 port
        maybe_warn_connectivity "$host" "$port" "HTTP"
        _frp_new_payload="$(service_payload http "$sid" HTTP "$host" "$port")"
        ;;
      3)
        frp_prompt_service_id https sid
        frp_prompt_target_host 127.0.0.1 host
        frp_prompt_target_port https 443 port
        maybe_warn_connectivity "$host" "$port" "HTTPS"
        _frp_new_payload="$(service_payload https "$sid" HTTPS "$host" "$port")"
        ;;
      4)
        frp_ux_service_id_help
        echo
        sid="$(read_tty "Service ID: " "")"
        name="$(read_tty "Display name [${sid}]: " "$sid")"
        frp_prompt_target_host 127.0.0.1 host
        frp_prompt_target_port custom "" port
        maybe_warn_connectivity "$host" "$port" "TCP"
        _frp_new_payload="$(service_payload custom "$sid" "$name" "$host" "$port")"
        ;;
      5)
        if [[ -n "$dest" ]]; then
          local -n _frp_payload_back="$dest"
          _frp_payload_back=""
        fi
        return 0
        ;;
      *) echo "ERROR: select 1-5" >&2; continue ;;
    esac
    if [[ -n "$dest" ]]; then
      local -n _frp_payload_out="$dest"
      _frp_payload_out="$_frp_new_payload"
    else
      printf '%s\n' "$_frp_new_payload"
    fi
    return 0
  done
}

frp_ux_print_install_summary() {
  local services_file="$1" version="${2:-0.70.1}"
  python3 - "$services_file" "$version" <<'PY'
import json, sys
from pathlib import Path
services = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
version = sys.argv[2]
labels = {'ssh': 'SSH / TCP', 'http': 'HTTP / TCP', 'https': 'HTTPS / TCP'}
print()
print('Ready to install')
print('================')
print()
print('The following services will be published:')
print()
for item in services:
    name = item.get('name') or item.get('id')
    preset = item.get('preset') or 'custom'
    kind = labels.get(preset, 'Custom TCP')
    print(name)
    print(f"  Type        : {kind}")
    print(f"  Target      : {item.get('local_ip')}:{item.get('local_port')}")
    print('  Public port : assigned automatically')
    print()
print('The public port is assigned automatically by the FRP server.')
print('You do not enter an external/public port here.')
print()
print('The installer will:')
print()
print(f'  - install FRP v{version}')
print('  - create /etc/frp/frpc.toml')
print('  - write /etc/frp/client-state.json')
print('  - install the frpc systemd service')
print('  - enable frpc at boot')
print('  - start the FRP client')
print()
PY
}

frp_ux_print_apply_summary() {
  frp_state_diff_engine summary "$1" "$2"
}

frp_atomic_write_text() {
  local dest="$1" mode="$2"
  python3 - "$dest" "$mode" <<'PY'
import os, sys, tempfile
from pathlib import Path
dest = Path(sys.argv[1])
mode = int(sys.argv[2], 8)
text = sys.stdin.read()
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

frp_atomic_copy_file() {
  local dest="$1" src="$2" mode="$3"
  python3 - "$dest" "$src" "$mode" <<'PY'
import os, sys, tempfile
from pathlib import Path
dest = Path(sys.argv[1])
src = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
text = src.read_text(encoding='utf-8')
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

frp_atomic_write_json_file() {
  local dest="$1" src="$2" mode="${3:-0600}"
  python3 - "$dest" "$src" "$mode" "${FRP_CLIENT_TEST_ROOT:-}" "${FRP_CLIENT_HOOK_STATE_WRITE:-}" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
dest = Path(sys.argv[1])
src = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
test_root = sys.argv[4]
hook = sys.argv[5]
data = json.loads(src.read_text(encoding='utf-8'))
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write('\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    if test_root and hook == '1' and dest.name == 'client-state.json':
        raise OSError('simulated state write failure')
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

frp_state_has_secrets() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
forbidden = {
    'token', 'auth.token', 'token_ciphertext', 'frp_token', 'server_token',
    'enrollment_code', 'enrollment_secret', 'enroll_secret', 'secret',
    'password', 'private_key', 'mgmt_mac_key', 'mac_key',
    'bootstrap_ticket', 'frp_bootstrap_ticket',
}
def walk(obj, path=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            loc = f'{path}.{k}' if path else str(k)
            if key in forbidden or 'token' in key or 'secret' in key or 'password' in key:
                raise SystemExit(f'secret field: {loc}')
            walk(v, loc)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            walk(v, f'{path}[{i}]')
raw = Path(sys.argv[1]).read_text(encoding='utf-8')
lower = raw.lower()
if 'begin ' in lower and 'private key' in lower:
    raise SystemExit('private key material')
walk(json.loads(raw))
PY
}

frp_services_to_list() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if isinstance(data, list):
    json.dump(data, sys.stdout)
    sys.stdout.write('\n')
    raise SystemExit(0)
if not isinstance(data, dict):
    raise SystemExit('ERROR: invalid services document')
services = data.get('services', data)
if isinstance(services, list):
    json.dump(services, sys.stdout)
    sys.stdout.write('\n')
    raise SystemExit(0)
out = []
for sid, item in services.items():
    rec = dict(item)
    rec['id'] = rec.get('id') or sid
    out.append(rec)
json.dump(out, sys.stdout)
sys.stdout.write('\n')
PY
}

frp_enabled_services_list() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if isinstance(data, dict) and 'services' in data:
    services = data['services']
    if isinstance(services, dict):
        items = []
        for sid, item in services.items():
            rec = dict(item)
            rec['id'] = rec.get('id') or sid
            items.append(rec)
        services = items
else:
    services = data
out = []
for item in services:
    if item.get('enabled', True) is False:
        continue
    out.append(item)
json.dump(out, sys.stdout)
sys.stdout.write('\n')
PY
}

frp_count_enabled_services() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
services = data.get('services', {}) if isinstance(data, dict) else data
n = 0
if isinstance(services, dict):
    for item in services.values():
        if item.get('enabled', True) is not False:
            n += 1
elif isinstance(services, list):
    for item in services:
        if item.get('enabled', True) is not False:
            n += 1
print(n)
PY
}

frp_load_client_state() {
  local path="$1"
  python3 - "$path" "$FRP_CLIENT_STATE_SCHEMA" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
want = int(sys.argv[2])
if not path.is_file():
    raise SystemExit(
        'ERROR: This client predates local management state.\n'
        'Re-enroll once with the current bootstrap installer to initialize frp-client management.'
    )
try:
    data = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    raise SystemExit('ERROR: client-state.json is not valid JSON')
if not isinstance(data, dict) or data.get('schema_version') != want:
    raise SystemExit(
        f'ERROR: unsupported client-state schema version {data.get("schema_version")!r}.\n'
        'Re-enroll once with the current bootstrap installer to initialize frp-client management.'
    )
if not isinstance(data.get('services'), dict):
    raise SystemExit('ERROR: client-state.json services must be a map')
PY
}

frp_write_client_state() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$FRP_CLIENT_STATE_SCHEMA" "$8" "${9:-tcp}" "${10:-}" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
dest, allocator_url, server, server_port, hostname, machine_id, host_id = sys.argv[1:8]
schema = int(sys.argv[8])
services_raw = json.loads(Path(sys.argv[9]).read_text(encoding='utf-8'))
transport = str(sys.argv[10] if len(sys.argv) > 10 else 'tcp').strip().lower() or 'tcp'
public_hostname = str(sys.argv[11] if len(sys.argv) > 11 else '').strip()
if transport not in ('tcp', 'wss'):
    raise SystemExit('ERROR: unsupported FRP transport')
services = {}
if isinstance(services_raw, list):
    items = services_raw
elif isinstance(services_raw, dict):
    items = []
    for sid, item in services_raw.items():
        rec = dict(item)
        rec['id'] = rec.get('id') or sid
        items.append(rec)
else:
    raise SystemExit('ERROR: invalid services for client-state')
for item in items:
    rec = {
        'id': item['id'],
        'name': item.get('name') or item['id'],
        'preset': item.get('preset') or 'custom',
        'protocol': 'tcp',
        'local_ip': item['local_ip'],
        'local_port': int(item['local_port']),
        'enabled': item.get('enabled', True) is not False,
    }
    if 'remote_port' in item and item['remote_port'] is not None:
        rec['remote_port'] = int(item['remote_port'])
    if rec['preset'] == 'ssh' and item.get('ssh_user'):
        rec['ssh_user'] = item['ssh_user']
    services[rec['id']] = rec
state = {
    'schema_version': schema,
    'allocator_url': allocator_url,
    'frp_server': server,
    'frp_server_port': int(server_port),
    'frp_transport': transport,
    'hostname': hostname,
    'machine_id': machine_id,
    'host_id': host_id,
    'services': services,
    'management_only': not any(
        rec.get('enabled', True) is not False for rec in services.values()
    ),
}
if public_hostname:
    state['public_hostname'] = public_hostname
dest = Path(dest)
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write('\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

services_init() {
  printf '%s\n' '[]' >"$SERVICES_FILE"
}

services_count() {
  python3 - "$SERVICES_FILE" <<'PY'
import json,sys
from pathlib import Path
print(len(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))))
PY
}

services_add_json() {
  python3 - "$SERVICES_FILE" "$1" <<'PY'
import json, re, sys
from pathlib import Path
path = Path(sys.argv[1])
raw = json.loads(sys.argv[2])
data = json.loads(path.read_text(encoding='utf-8'))
sid = str(raw.get('id', '')).strip().lower()
if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,31}', sid or ''):
    raise SystemExit('ERROR: invalid service id; use [a-z0-9][a-z0-9._-]{0,31}')
if any(item.get('id') == sid for item in data):
    raise SystemExit(
        f'ERROR: duplicate service id: {sid}\n\n'
        'A service with this ID already exists.\n'
        'Service IDs are lowercase and case-insensitive.'
    )
protocol = str(raw.get('protocol', 'tcp') or 'tcp').strip().lower()
if protocol != 'tcp':
    raise SystemExit('ERROR: only tcp services are supported')
preset = str(raw.get('preset', 'custom') or 'custom').strip().lower()
if preset not in ('ssh', 'http', 'https', 'custom'):
    raise SystemExit('ERROR: invalid service preset')
name = str(raw.get('name', '') or sid).strip() or sid
if len(name) > 64 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name):
    raise SystemExit('ERROR: invalid service display name')
local_ip = str(raw.get('local_ip', '')).strip()
if (not local_ip or len(local_ip) > 253
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in local_ip)
        or any(c in local_ip for c in ' /\\;|&$`\'"<>')):
    raise SystemExit('ERROR: invalid target host')
try:
    local_port = int(str(raw.get('local_port', '')).strip())
except Exception:
    raise SystemExit('ERROR: invalid local_port; must be an integer 1-65535')
if local_port < 1 or local_port > 65535:
    raise SystemExit('ERROR: invalid local_port; must be an integer 1-65535')
item = {
    'id': sid,
    'name': name,
    'protocol': 'tcp',
    'local_ip': local_ip,
    'local_port': local_port,
    'preset': preset,
}
if preset == 'ssh':
    ssh_user = str(raw.get('ssh_user', '') or '').strip()
    if not ssh_user:
        raise SystemExit('ERROR: ssh_user is required for ssh services')
    if not re.fullmatch(r'[A-Za-z0-9._@-]{1,32}', ssh_user):
        raise SystemExit('ERROR: invalid ssh_user')
    item['ssh_user'] = ssh_user
if len(data) >= 32:
    raise SystemExit('ERROR: too many services')
data.append(item)
path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
PY
}

services_load_from_env() {
  python3 - "$SERVICES_FILE" <<'PY'
import json, os, re, sys
from pathlib import Path

def add(path, raw):
    data = json.loads(path.read_text(encoding='utf-8'))
    sid = str(raw.get('id', '')).strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,31}', sid or ''):
        raise SystemExit('ERROR: invalid service id; use [a-z0-9][a-z0-9._-]{0,31}')
    if any(item.get('id') == sid for item in data):
        raise SystemExit(
            f'ERROR: duplicate service id: {sid}\n\n'
            'A service with this ID already exists.\n'
            'Service IDs are lowercase and case-insensitive.'
        )
    protocol = str(raw.get('protocol', 'tcp') or 'tcp').strip().lower()
    if protocol != 'tcp':
        raise SystemExit('ERROR: only tcp services are supported')
    preset = str(raw.get('preset', 'custom') or 'custom').strip().lower()
    if preset not in ('ssh', 'http', 'https', 'custom'):
        raise SystemExit('ERROR: invalid service preset')
    name = str(raw.get('name', '') or sid).strip() or sid
    if len(name) > 64 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name):
        raise SystemExit('ERROR: invalid service display name')
    local_ip = str(raw.get('local_ip', '')).strip()
    if (not local_ip or len(local_ip) > 253
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in local_ip)
            or any(c in local_ip for c in ' /\\;|&$`\'"<>')):
        raise SystemExit('ERROR: invalid target host')
    try:
        local_port = int(str(raw.get('local_port', '')).strip())
    except Exception:
        raise SystemExit('ERROR: invalid local_port; must be an integer 1-65535')
    if local_port < 1 or local_port > 65535:
        raise SystemExit('ERROR: invalid local_port; must be an integer 1-65535')
    item = {
        'id': sid,
        'name': name,
        'protocol': 'tcp',
        'local_ip': local_ip,
        'local_port': local_port,
        'preset': preset,
    }
    if preset == 'ssh':
        ssh_user = str(raw.get('ssh_user', '') or '').strip()
        if not ssh_user:
            raise SystemExit('ERROR: ssh_user is required for ssh services')
        if not re.fullmatch(r'[A-Za-z0-9._@-]{1,32}', ssh_user):
            raise SystemExit('ERROR: invalid ssh_user')
        item['ssh_user'] = ssh_user
    if len(data) >= 32:
        raise SystemExit('ERROR: too many services')
    data.append(item)
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')

path = Path(sys.argv[1])
try:
    raw = json.loads(os.environ.get('FRP_SERVICES_JSON', ''))
except json.JSONDecodeError:
    raise SystemExit('ERROR: FRP_SERVICES_JSON is not valid JSON')
if not isinstance(raw, list):
    raise SystemExit('ERROR: FRP_SERVICES_JSON must be a list')
path.write_text('[]\n', encoding='utf-8')
for item in raw:
    add(path, item)
PY
}

services_list() {
  python3 - "$SERVICES_FILE" <<'PY'
import json,sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if not data:
    print('(none)')
    raise SystemExit(0)
labels = {'ssh': 'SSH / TCP', 'http': 'HTTP / TCP', 'https': 'HTTPS / TCP'}
for i, item in enumerate(data, 1):
    preset = item.get('preset') or 'custom'
    print(f"{i}. {item.get('id')}")
    print(f"   Type   : {labels.get(preset, 'Custom TCP')}")
    print(f"   Target : {item.get('local_ip')}:{item.get('local_port')}")
    print()
PY
}

services_remove_index() {
  python3 - "$SERVICES_FILE" "$1" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1])
data=json.loads(path.read_text(encoding='utf-8'))
try:
    idx=int(sys.argv[2])
except Exception:
    raise SystemExit('ERROR: invalid service number')
if idx < 1 or idx > len(data):
    raise SystemExit('ERROR: service number out of range')
data.pop(idx-1)
path.write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
PY
}

merge_allocated_services() {
  python3 - "$SERVICES_FILE" "$ALLOCATED_FILE" <<'PY'
import json,sys
from pathlib import Path
local_path, alloc_path = Path(sys.argv[1]), Path(sys.argv[2])
local = json.loads(local_path.read_text(encoding='utf-8'))
allocated = json.loads(alloc_path.read_text(encoding='utf-8'))
if not isinstance(allocated, list):
    raise SystemExit('ERROR: allocator response services are invalid')
by_id = {}
for item in allocated:
    sid = str(item.get('id', '')).strip()
    if not sid:
        raise SystemExit('ERROR: allocator response is missing a service id')
    if 'remote_port' not in item:
        raise SystemExit(f'ERROR: allocator response is missing remote_port for {sid}')
    by_id[sid] = int(item['remote_port'])
if len(by_id) != len(local):
    raise SystemExit('ERROR: allocator did not return every requested service')
for item in local:
    sid = item['id']
    if sid not in by_id:
        raise SystemExit(f'ERROR: allocator did not allocate a port for {sid}')
    item['remote_port'] = by_id[sid]
local_path.write_text(json.dumps(local, indent=2)+'\n', encoding='utf-8')
PY
}

render_frpc_toml() {
  local dest="$1" server="$2" server_port="$3" token="$4" host_id="$5" services_json_file="$6"
  local transport="${7:-}"
  local ca_file=""
  if [[ -z "$transport" ]]; then
    transport=tcp
  fi
  transport="$(printf '%s' "$transport" | tr '[:upper:]' '[:lower:]')"
  case "$transport" in
    tcp|wss) ;;
    *)
      echo "ERROR: unsupported FRP transport ${transport}" >&2
      return 1
      ;;
  esac
  if [[ "$transport" == "wss" ]]; then
    ca_file="$(frp_allocator_ca_path)"
    if [[ ! -f "$ca_file" ]]; then
      echo "ERROR: allocator CA is required for WSS FRP control" >&2
      return 1
    fi
  fi
  python3 - "$dest" "$server" "$server_port" "$token" "$host_id" "$services_json_file" "$transport" "$ca_file" <<'PY'
import json, sys
from pathlib import Path
dest, server, server_port, token, host_id, svc_path, transport, ca_file = sys.argv[1:9]
raw = json.loads(Path(svc_path).read_text(encoding='utf-8'))
if isinstance(raw, dict) and 'services' in raw:
    services = []
    for sid, item in raw['services'].items():
        rec = dict(item)
        rec['id'] = rec.get('id') or sid
        services.append(rec)
else:
    services = raw
lines = [
    f'serverAddr = "{server}"',
    f'serverPort = {server_port}',
    '',
    'auth.method = "token"',
    f'auth.token = "{token}"',
    '',
    'transport.tls.enable = true',
]
if transport == 'wss':
    lines.extend([
        'transport.protocol = "wss"',
        f'transport.tls.trustedCaFile = "{ca_file}"',
    ])
for item in services:
    if item.get('enabled', True) is False:
        continue
    lines.extend([
        '',
        '[[proxies]]',
        f'name = "{host_id}-{item["id"]}"',
        'type = "tcp"',
        f'localIP = "{item["local_ip"]}"',
        f'localPort = {int(item["local_port"])}',
        f'remotePort = {int(item["remote_port"])}',
    ])
text = '\n'.join(lines) + '\n'
path = Path(dest)
path.parent.mkdir(parents=True, exist_ok=True)
import os, tempfile
fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
PY
}

render_access_info() {
  local dest="$1" server="$2" services_json_file="$3"
  local public_hostname="${4:-}"
  if [[ -z "$public_hostname" && -f "$services_json_file" ]]; then
    public_hostname="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); print(d.get("public_hostname","") if isinstance(d,dict) else "")' "$services_json_file" 2>/dev/null || true)"
  fi
  python3 - "$dest" "$server" "$services_json_file" "$public_hostname" <<'PY'
import json,sys
from pathlib import Path
dest, server, svc_path, alias = sys.argv[1:5]
raw = json.loads(Path(svc_path).read_text(encoding='utf-8'))
if isinstance(raw, dict) and 'services' in raw:
    services = []
    for sid, item in raw['services'].items():
        rec = dict(item)
        rec['id'] = rec.get('id') or sid
        services.append(rec)
    if not alias:
        alias = str(raw.get('public_hostname') or '')
else:
    services = raw
lines = [f'FRP Server: {server}', '', 'Services:', '']
def clean(value, limit=253):
    text = str(value or '')
    return ''.join(' ' if ord(c) < 32 or 127 <= ord(c) <= 159 else c for c in text)[:limit].strip()
def is_ipv6(host):
    text = str(host or '')
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    try:
        import ipaddress
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except Exception:
        return False
def fmt_host(host):
    host = clean(host)
    if is_ipv6(host) and not (host.startswith('[') and host.endswith(']')):
        return '[' + host + ']'
    return host
def host_port(host, port):
    return f'{fmt_host(host)}:{port}'
def http_url(scheme, host, port):
    return f'{scheme}://{host_port(host, port)}'
server = clean(server)
alias = clean(alias)
https_guidance_shown = False
for item in services:
    if item.get('enabled', True) is False:
        continue
    sid = clean(item['id'], 32)
    name = clean(item.get('name') or sid, 64)
    preset = item.get('preset') or 'custom'
    local_ip = clean(item.get('local_ip'))
    local_port = item.get('local_port')
    remote_port = item.get('remote_port')
    lines.append(sid if name == sid else f'{sid} ({name})')
    lines.append(f'  Target : {local_ip}:{local_port}')
    preferred = alias if alias and alias != server else ''
    if preferred:
        lines.append(f'  Public : {host_port(preferred, remote_port)}')
        lines.append(f'  Fallback public : {host_port(server, remote_port)}')
    else:
        lines.append(f'  Public : {host_port(server, remote_port)}')
    if preset == 'ssh':
        user = clean(item.get('ssh_user'), 32)
        if user:
            lines.append('  Connect:')
            if preferred:
                lines.append('    Preferred:')
                lines.append(f'      ssh -p {remote_port} {user}@{preferred}')
                lines.append('    Fallback:')
                lines.append(f'      ssh -p {remote_port} {user}@{server}')
            else:
                lines.append(f'    ssh -p {remote_port} {user}@{server}')
        else:
            lines.append('  SSH user: legacy / unspecified')
    elif preset == 'http':
        lines.append('  URL:')
        if preferred:
            lines.append('    Preferred:')
            lines.append(f'      {http_url("http", preferred, remote_port)}')
            lines.append('    Fallback:')
            lines.append(f'      {http_url("http", server, remote_port)}')
        else:
            lines.append(f'    {http_url("http", server, remote_port)}')
    elif preset == 'https':
        lines.append('  URL:')
        if preferred:
            lines.append('    Preferred:')
            lines.append(f'      {http_url("https", preferred, remote_port)}')
            lines.append('    Fallback:')
            lines.append(f'      {http_url("https", server, remote_port)}')
        else:
            lines.append(f'    {http_url("https", server, remote_port)}')
        if preferred and not https_guidance_shown:
            lines.append('  Note:')
            lines.append('    TLS is passed through to the target HTTPS service.')
            lines.append(f'    To avoid certificate warnings, the target service certificate')
            lines.append(f'    must be valid for {preferred}.')
            https_guidance_shown = True
    else:
        lines.append('  Connect:')
        if preferred:
            lines.append('    Preferred:')
            lines.append(f'      {host_port(preferred, remote_port)}')
            lines.append('    Fallback:')
            lines.append(f'      {host_port(server, remote_port)}')
        else:
            lines.append(f'    {host_port(server, remote_port)}')
    lines.append('')
path = Path(dest)
path.parent.mkdir(parents=True, exist_ok=True)
import os, tempfile
text = '\n'.join(lines).rstrip() + '\n'
fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
PY
}

proxy_names_from_services() {
  local host_id="$1"
  python3 - "$host_id" "$SERVICES_FILE" <<'PY'
import json,sys
from pathlib import Path
host_id=sys.argv[1]
raw=json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
if isinstance(raw, dict) and 'services' in raw:
    services=[]
    for sid, item in raw['services'].items():
        rec=dict(item)
        rec['id']=rec.get('id') or sid
        services.append(rec)
else:
    services=raw
for item in services:
    if item.get('enabled', True) is False:
        continue
    print(f'{host_id}-{item["id"]}')
PY
}

wait_for_proxies() {
  local logs proxy missing
  local -a names=("$@")
  local i
  for i in {1..20}; do
    sleep 1
    if frp_is_darwin; then
      logs="$(frp_macos_recent_logs 400 2>/dev/null || true)"
    else
      logs="$(journalctl -u frpc -n 400 --no-pager 2>/dev/null || true)"
    fi
    if ! grep -q 'login to server success' <<<"$logs"; then
      continue
    fi
    missing=""
    for proxy in "${names[@]}"; do
      if ! grep -F "[${proxy}] start proxy success" <<<"$logs"; then
        missing="$proxy"
        break
      fi
    done
    if [[ -z "$missing" ]]; then
      return 0
    fi
  done
  return 1
}

frp_zero_touch_active() {
  [[ "${FRP_ZERO_TOUCH:-}" == "1" ]] || [[ -n "${FRP_BOOTSTRAP_TICKET:-}" ]]
}

frp_zero_touch_apply_package() {
  # Decode opaque zt1.<payload> from short Zero-Touch command into env vars.
  # Never uses insecure TLS; CA pin and allocator URL come from the package.
  local package="${1:-}"
  local decoded
  if [[ -z "$package" ]]; then
    echo "ERROR: zero-touch package is empty." >&2
    frp_emit_failure_class ZERO_TOUCH_INPUT_INVALID
    return 1
  fi
  if ! decoded="$(python3 - "$package" <<'PY'
import base64
import json
import sys

text = sys.argv[1].strip()
parts = text.split('.', 1)
if len(parts) != 2 or parts[0] != 'zt1' or not parts[1]:
    raise SystemExit('invalid zero-touch package')
padded = parts[1] + ('=' * (-len(parts[1]) % 4))
try:
    raw = base64.urlsafe_b64decode(padded.encode('ascii'))
    payload = json.loads(raw.decode('utf-8'))
except Exception:
    raise SystemExit('invalid zero-touch package')
if not isinstance(payload, dict) or int(payload.get('v') or 0) != 1:
    raise SystemExit('unsupported zero-touch package version')
url = str(payload.get('u') or '').strip()
ca = str(payload.get('c') or '').strip().lower()
ticket = str(payload.get('t') or '').strip()
if not url.lower().startswith('https://') or len(ca) != 64 or not ticket:
    raise SystemExit('incomplete zero-touch package')
if any(ch not in '0123456789abcdef' for ch in ca):
    raise SystemExit('invalid CA fingerprint in zero-touch package')
# Emit shell-safe assignments (no secrets in argv of subsequent tools beyond env).
def sh_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"
print('FRP_ALLOCATOR_URL=%s' % sh_quote(url))
print('FRP_ALLOCATOR_CA_SHA256=%s' % sh_quote(ca))
print('FRP_BOOTSTRAP_TICKET=%s' % sh_quote(ticket))
print('FRP_ZERO_TOUCH=1')
PY
)"; then
    echo "ERROR: invalid zero-touch package." >&2
    frp_emit_failure_class ZERO_TOUCH_INPUT_INVALID
    return 1
  fi
  eval "$decoded"
  export FRP_ALLOCATOR_URL FRP_ALLOCATOR_CA_SHA256 FRP_BOOTSTRAP_TICKET FRP_ZERO_TOUCH
  return 0
}

frp_zero_touch_require_inputs() {
  if [[ -z "${FRP_BOOTSTRAP_TICKET:-}" ]]; then
    echo "ERROR: zero-touch setup requires FRP_BOOTSTRAP_TICKET." >&2
    echo "Paste the full one-line command from the FRP server." >&2
    echo "Setup could not continue because required bootstrap data is missing." >&2
    frp_emit_failure_class ZERO_TOUCH_INPUT_INVALID
    return 1
  fi
  if [[ -z "${FRP_ALLOCATOR_CA_SHA256:-}" && -z "${FRP_ALLOCATOR_CA_FILE:-}" ]]; then
    echo "ERROR: zero-touch setup requires FRP_ALLOCATOR_CA_SHA256." >&2
    frp_emit_failure_class ZERO_TOUCH_INPUT_INVALID
    return 1
  fi
  return 0
}

frp_zero_touch_ssh_preflight() {
  local user="${1:-}" port="${2:-22}"
  local class=""
  if [[ -z "$user" ]]; then
    return 0
  fi
  if class="$(python3 - "$user" "$port" <<'PY'
import pwd
import re
import socket
import sys

user = sys.argv[1]
try:
    port = int(sys.argv[2])
except (TypeError, ValueError):
    sys.stdout.write('SSH_TARGET_UNAVAILABLE')
    raise SystemExit(4)
if not re.fullmatch(r'[A-Za-z0-9._@-]{1,32}', user):
    sys.stdout.write('SSH_USER_NOT_FOUND')
    raise SystemExit(2)
try:
    pwd.getpwnam(user)
except KeyError:
    sys.stdout.write('SSH_USER_NOT_FOUND')
    raise SystemExit(3)
except Exception:
    sys.stdout.write('SSH_USER_NOT_FOUND')
    raise SystemExit(3)
if port < 1 or port > 65535:
    sys.stdout.write('SSH_TARGET_UNAVAILABLE')
    raise SystemExit(4)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect(('127.0.0.1', port))
except Exception:
    sys.stdout.write('SSH_TARGET_UNAVAILABLE')
    raise SystemExit(4)
finally:
    try:
        sock.close()
    except Exception:
        pass
raise SystemExit(0)
PY
)"; then
    return 0
  fi
  case "$class" in
    SSH_USER_NOT_FOUND)
      echo "Setup could not continue because the SSH user '${user}' does not exist on this host." >&2
      echo >&2
      echo "No FRP port was allocated." >&2
      echo "The one-time setup command may be run again before it expires after the user exists." >&2
      echo >&2
      frp_emit_failure_class SSH_USER_NOT_FOUND
      return 1
      ;;
    SSH_TARGET_UNAVAILABLE)
      echo "Setup could not continue because SSH is not listening on 127.0.0.1:${port}." >&2
      echo >&2
      echo "No FRP port was allocated." >&2
      echo "The one-time setup command may be run again before it expires after SSH is available." >&2
      echo >&2
      frp_emit_failure_class SSH_TARGET_UNAVAILABLE
      return 1
      ;;
    *)
      echo "Setup could not continue because SSH is not ready on this host." >&2
      echo >&2
      echo "No FRP port was allocated." >&2
      echo "The one-time setup command may be run again before it expires after SSH is available." >&2
      echo >&2
      frp_emit_failure_class SSH_TARGET_UNAVAILABLE
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Crash-safe pending enrollment transaction (Finding A: Zero-Touch lost-
# response recovery).
#
# If the HTTPS response from /bootstrap/redeem or /enroll is lost, or the
# client process crashes/is killed after the server has committed but before
# local state (client-state.json + frpc.toml + management identity) is
# written, the Enrollment Code/Secret and the exact request that was
# authorized must not be lost. Losing them makes exact retry impossible,
# because a used Bootstrap Ticket cannot be redeemed again and a fresh
# Enrollment Code changes the authorized identity.
#
# This pending file preserves the minimum needed for exact retry: the
# enrollment id/secret pair, machine id, hostname, the exact services
# snapshot (and its digest) that was authorized, the management-key
# fingerprint when a local identity exists, and the operation phase. It is
# written atomically, root-owned, mode 0600, under frp_client_path (so it
# honors FRP_CLIENT_TEST_ROOT in tests) and is cleared only after local state
# has been committed successfully. It never weakens ticket single-use
# semantics: the pending file only lets the client skip the (now consumed)
# /bootstrap/redeem call and replay the already-authorized /enroll exactly,
# which the allocator independently recognizes as an idempotent replay of a
# used Enrollment Code (frp-port-allocator.py _used_enrollment_idempotent_replay).
frp_pending_enroll_exists_for() {
  local machine_id="$1" path
  path="$(frp_pending_enroll_path)"
  [[ -f "$path" ]] || return 1
  python3 - "$path" "$machine_id" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(1)
if not isinstance(data, dict):
    raise SystemExit(1)
if str(data.get('machine_id') or '') != sys.argv[2]:
    raise SystemExit(1)
if str(data.get('phase') or '') not in ('redeemed', 'enrolled'):
    raise SystemExit(1)
if not data.get('enroll_id') or not data.get('enroll_secret'):
    raise SystemExit(1)
PY
}

frp_pending_enroll_write() {
  # Args: phase machine_id hostname_value allocator_url enroll_id enroll_secret
  #       services_file [allocated_file] [meta_file]
  # The secret is passed via environment, not argv, to keep it out of any
  # process listing.
  local phase="$1" machine_id="$2" hostname_value="$3" allocator_url="$4"
  local enroll_id="$5" enroll_secret="$6" services_file="$7"
  local allocated_file="${8:-}" meta_file="${9:-}"
  local dest mgmt_fp
  dest="$(frp_pending_enroll_path)"
  mkdir -p "$(dirname "$dest")"
  mgmt_fp="$(frp_identity_public_fingerprint 2>/dev/null || true)"
  # NOTE: use a private env var name for the secret, not ENROLL_SECRET -
  # callers hold their own global ENROLL_SECRET and `unset ENROLL_SECRET`
  # below would otherwise clobber it (no `local` scope for env assignments).
  _FRP_PENDING_ENROLL_SECRET="$enroll_secret" python3 - "$dest" "$phase" "$machine_id" "$hostname_value" \
    "$allocator_url" "$enroll_id" "$services_file" "$mgmt_fp" \
    "$allocated_file" "$meta_file" <<'PY'
import hashlib, json, os, sys, tempfile, time
from pathlib import Path

dest = Path(sys.argv[1])
phase = sys.argv[2]
machine_id = sys.argv[3]
hostname_value = sys.argv[4]
allocator_url = sys.argv[5]
enroll_id = sys.argv[6]
services_file = sys.argv[7]
mgmt_fp = sys.argv[8]
allocated_file = sys.argv[9]
meta_file = sys.argv[10]
secret = os.environ.get('_FRP_PENDING_ENROLL_SECRET', '')

services = []
if services_file:
    sp = Path(services_file)
    if sp.is_file():
        try:
            services = json.loads(sp.read_text(encoding='utf-8'))
        except Exception:
            services = []
if isinstance(services, dict):
    services = services.get('services', services)
digest = hashlib.sha256(
    json.dumps(services, sort_keys=True, separators=(',', ':')).encode('utf-8')
).hexdigest()

record = {}
if dest.is_file():
    try:
        existing = json.loads(dest.read_text(encoding='utf-8'))
        if isinstance(existing, dict):
            record = existing
    except Exception:
        record = {}

now = int(time.time())
record['schema_version'] = 1
record.setdefault('created_at', now)
record['updated_at'] = now
record['phase'] = phase
record['machine_id'] = machine_id
record['hostname'] = hostname_value
record['allocator_url'] = allocator_url
record['enroll_id'] = enroll_id
record['enroll_secret'] = secret
record['services'] = services
record['services_digest'] = digest
if mgmt_fp:
    record['mgmt_fingerprint'] = mgmt_fp
else:
    record.pop('mgmt_fingerprint', None)

if allocated_file:
    ap = Path(allocated_file)
    if ap.is_file():
        try:
            record['allocated_services'] = json.loads(ap.read_text(encoding='utf-8'))
        except Exception:
            pass
if meta_file:
    mp = Path(meta_file)
    if mp.is_file():
        try:
            record['enroll_meta'] = json.loads(mp.read_text(encoding='utf-8'))
        except Exception:
            pass

dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write('\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
  unset _FRP_PENDING_ENROLL_SECRET
}

frp_pending_enroll_load() {
  # Args: machine_id services_out allocated_out meta_out phase_var enroll_id_var enroll_secret_var
  # On success, writes the pending services snapshot to services_out (always)
  # and, when the cached phase is "enrolled" with a usable cached response,
  # writes allocated_out/meta_out so the caller can finish the local commit
  # without another /enroll round trip. Falls back to phase "redeemed" (exact
  # replay via /enroll) when the cached response is missing or incomplete.
  local machine_id="$1" services_out="$2" allocated_out="$3" meta_out="$4"
  local phase_var="$5" enroll_id_var="$6" enroll_secret_var="$7"
  local path parsed
  path="$(frp_pending_enroll_path)"
  [[ -f "$path" ]] || return 1
  parsed="$(python3 - "$path" "$machine_id" "$services_out" "$allocated_out" "$meta_out" <<'PY'
import json, sys
from pathlib import Path

path, machine_id, services_out, allocated_out, meta_out = sys.argv[1:6]
try:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
except Exception:
    print('ERR')
    raise SystemExit(0)
if not isinstance(data, dict) or str(data.get('machine_id') or '') != machine_id:
    print('ERR')
    raise SystemExit(0)

phase = str(data.get('phase') or '')
enroll_id = str(data.get('enroll_id') or '')
enroll_secret = str(data.get('enroll_secret') or '')
if phase not in ('redeemed', 'enrolled') or not enroll_id or not enroll_secret:
    print('ERR')
    raise SystemExit(0)

services = data.get('services')
if not isinstance(services, list):
    services = []
Path(services_out).write_text(json.dumps(services, indent=2) + '\n', encoding='utf-8')

if phase == 'enrolled':
    allocated = data.get('allocated_services')
    meta = data.get('enroll_meta')
    usable = (
        isinstance(allocated, list)
        and isinstance(meta, dict)
        and meta.get('token_ciphertext')
        and meta.get('frp_server')
        and meta.get('frp_server_port')
    )
    if usable:
        Path(allocated_out).write_text(json.dumps(allocated) + '\n', encoding='utf-8')
        Path(meta_out).write_text(json.dumps(meta) + '\n', encoding='utf-8')
    else:
        # Cached response is incomplete; fall back to an exact /enroll replay.
        phase = 'redeemed'

print('OK\t%s\t%s\t%s' % (phase, enroll_id, enroll_secret))
PY
)"
  [[ "$parsed" == OK$'\t'* ]] || return 1
  local p e s
  p="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $2}')"
  e="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $3}')"
  s="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $4}')"
  printf -v "$phase_var" '%s' "$p"
  printf -v "$enroll_id_var" '%s' "$e"
  printf -v "$enroll_secret_var" '%s' "$s"
  return 0
}

frp_pending_enroll_allocator_url() {
  # Best-effort fallback so a bare resume (no re-supplied environment) can
  # still find the same allocator without requiring the admin to remember
  # FRP_ALLOCATOR_URL from the original attempt.
  local path
  path="$(frp_pending_enroll_path)"
  [[ -f "$path" ]] || return 1
  python3 -c '
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
url = str(data.get("allocator_url") or "") if isinstance(data, dict) else ""
if not url:
    raise SystemExit(1)
sys.stdout.write(url)
' "$path" 2>/dev/null
}

frp_pending_enroll_read() {
  local path
  path="$(frp_pending_enroll_path)"
  [[ -f "$path" ]] || return 1
  python3 -c '
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(data, dict):
    raise SystemExit(1)
print(json.dumps(data))
' "$path"
}

frp_pending_enroll_clear() {
  local path
  path="$(frp_pending_enroll_path)"
  rm -f "$path" 2>/dev/null || true
}

frp_redeem_bootstrap_ticket() {
  local allocator_url="$1" machine_id="$2" hostname_value="$3"
  local services_file="$4" enroll_id_var="$5" enroll_secret_var="$6"
  local origin redeem_url req_dir req_file resp_file curl_err response
  local parsed_id parsed_secret error_class error_msg

  frp_client_hook_log bootstrap_redeem
  if [[ -z "${FRP_BOOTSTRAP_TICKET:-}" ]]; then
    echo "ERROR: bootstrap ticket is missing." >&2
    frp_emit_failure_class ZERO_TOUCH_INPUT_INVALID
    return 1
  fi
  origin="$(frp_allocator_origin_url "$allocator_url")" || {
    echo "ERROR: cannot derive allocator origin from URL" >&2
    frp_emit_failure_class BOOTSTRAP_REDEEM_FAILED
    return 1
  }
  redeem_url="${origin}/bootstrap/redeem"
  req_dir="$(frp_secure_mktemp_dir)"
  req_file="${req_dir}/redeem.json"
  resp_file="${req_dir}/redeem-resp.json"
  curl_err="${req_dir}/curl.err"
  chmod 700 "$req_dir"

  MACHINE_ID="$machine_id" HOSTNAME_VALUE="$hostname_value" \
    FRP_BOOTSTRAP_TICKET="${FRP_BOOTSTRAP_TICKET}" python3 - "$req_file" <<'PY'
import json, os, sys
from pathlib import Path
ticket = os.environ.get('FRP_BOOTSTRAP_TICKET', '')
payload = {
    'ticket': ticket,
    'machine_id': os.environ.get('MACHINE_ID', ''),
    'hostname': os.environ.get('HOSTNAME_VALUE', ''),
}
path = Path(sys.argv[1])
path.write_text(json.dumps(payload, separators=(',', ':')) + '\n', encoding='utf-8')
path.chmod(0o600)
PY

  if ! response="$(frp_allocator_curl \
    -X POST \
    -H 'Content-Type: application/json' \
    --data-binary @"$req_file" \
    "$redeem_url" 2>"$curl_err")"; then
    frp_explain_allocator_curl_error "$curl_err"
    rm -rf "$req_dir"
    unset FRP_BOOTSTRAP_TICKET
    frp_emit_failure_class BOOTSTRAP_REDEEM_FAILED
    return 1
  fi
  unset FRP_BOOTSTRAP_TICKET
  rm -f "$req_file"
  printf '%s\n' "$response" >"$resp_file"
  chmod 600 "$resp_file"

  parsed="$(python3 - "$resp_file" "$services_file" <<'PY'
import json, sys
from pathlib import Path
raw = Path(sys.argv[1]).read_text(encoding='utf-8')
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    print('ERR\tZERO_TOUCH_INPUT_INVALID\tinvalid bootstrap response')
    raise SystemExit(1)
if not isinstance(data, dict):
    print('ERR\tBOOTSTRAP_REDEEM_FAILED\tinvalid bootstrap response')
    raise SystemExit(1)
if data.get('error'):
    cls = str(data.get('error_class') or 'BOOTSTRAP_REDEEM_FAILED')
    msg = str(data.get('error') or 'bootstrap redeem failed')
    print('ERR\t%s\t%s' % (cls, msg.replace('\t', ' ')))
    raise SystemExit(1)
code = str(data.get('enrollment_code') or '')
if '.' not in code:
    print('ERR\tBOOTSTRAP_REDEEM_FAILED\tbootstrap response is missing enrollment data')
    raise SystemExit(1)
eid, secret = code.split('.', 1)
if not eid or not secret:
    print('ERR\tBOOTSTRAP_REDEEM_FAILED\tbootstrap response is missing enrollment data')
    raise SystemExit(1)
services = data.get('services')
if not isinstance(services, list):
    print('ERR\tBOOTSTRAP_REDEEM_FAILED\tbootstrap response is missing services')
    raise SystemExit(1)
Path(sys.argv[2]).write_text(json.dumps(services, indent=2) + '\n', encoding='utf-8')
print('OK\t%s\t%s' % (eid, secret))
PY
)" || true

  rm -rf "$req_dir"
  if [[ "$parsed" != OK$'\t'* ]]; then
    error_class="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $2}')"
    error_msg="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $3}')"
    error_class="${error_class:-BOOTSTRAP_REDEEM_FAILED}"
    echo "ERROR: ${error_msg:-bootstrap redeem failed}" >&2
    case "$error_class" in
      BOOTSTRAP_TICKET_EXPIRED)
        echo "The one-time setup command has expired. Ask the administrator for a new command." >&2
        ;;
      BOOTSTRAP_TICKET_BOUND)
        echo "This setup command was already used on another machine." >&2
        ;;
      BOOTSTRAP_TICKET_USED)
        echo "This setup command has already completed enrollment and cannot be reused." >&2
        ;;
      BOOTSTRAP_TICKET_INVALID)
        echo "The one-time setup command is not valid." >&2
        ;;
    esac
    frp_emit_failure_class "$error_class"
    return 1
  fi
  parsed_id="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $2}')"
  parsed_secret="$(printf '%s' "$parsed" | awk -F'\t' 'NR==1{print $3}')"
  printf -v "$enroll_id_var" '%s' "$parsed_id"
  printf -v "$enroll_secret_var" '%s' "$parsed_secret"
  return 0
}

frp_client_apply_reconcile_runtime() {
  local dropped="$1" toml token
  [[ "$dropped" == 1 ]] || return 0
  toml="$(frp_client_toml_path)"
  [[ -f "$toml" ]] || return 0
  token="$(frp_token_from_toml_file "$toml" || true)"
  [[ -n "$token" ]] || return 0
  frp_regenerate_toml_from_state "$token" || return 0
  frp_regenerate_access_from_state || true
  frp_client_restart || true
}

frp_client_reconcile_released_services() {
  local path allocator_url machine_id hostname_value request timestamp signature nonce response curl_err py key_path mac
  local dropped_marker dropped=0
  path="$(frp_client_state_path)"
  [[ -f "$path" ]] || return 0
  if [[ "${FRP_SKIP_CONNECTIVITY_CHECK:-}" == "1" ]]; then
    return 0
  fi
  if ! python3 - "$path" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
services = state.get('services') or {}
if not isinstance(services, dict) or not services:
    raise SystemExit(1)
PY
  then
    return 0
  fi

  if [[ -n "${FRP_CLIENT_RECONCILE_REGISTRY_IDS:-}" ]]; then
    dropped_marker="$(
      REGISTRY_IDS="$FRP_CLIENT_RECONCILE_REGISTRY_IDS" STATE_PATH="$path" python3 - <<'PY'
import json, os
from pathlib import Path
state = json.loads(Path(os.environ['STATE_PATH']).read_text(encoding='utf-8'))
ids = set(json.loads(os.environ['REGISTRY_IDS']))
services = state.get('services') or {}
dropped_enabled = False
for sid in list(services.keys()):
    rec = services.get(sid) or {}
    if sid not in ids:
        if rec.get('enabled', True) is not False:
            dropped_enabled = True
        services.pop(sid, None)
state['services'] = services
Path(os.environ['STATE_PATH']).write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print('DROPPED_ENABLED=1' if dropped_enabled else 'DROPPED_ENABLED=0')
PY
    )"
    [[ "$dropped_marker" == *DROPPED_ENABLED=1* ]] && dropped=1
    frp_client_apply_reconcile_runtime "$dropped"
    return 0
  fi

  if [[ "$(frp_identity_status)" != enrolled ]]; then
    return 0
  fi

  allocator_url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("allocator_url") or "")' "$path")"
  machine_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("machine_id") or "")' "$path")"
  hostname_value="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("hostname") or "")' "$path")"
  [[ -n "$allocator_url" && -n "$machine_id" ]] || return 0

  request="$(python3 - "$machine_id" "$hostname_value" <<'PY'
import json, sys
print(json.dumps({
  'machine_id': sys.argv[1],
  'hostname': sys.argv[2],
}, separators=(',', ':')))
PY
)"
  timestamp="$(date +%s)"
  py="$(frp_mgmt_auth_py)" || return 0
  key_path="$(frp_client_identity_key_path)" || return 0
  nonce="$(python3 - "$py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('frp_mgmt_auth', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.new_nonce())
PY
)"
  signature="$(BODY="$request" python3 - "$py" "$key_path" "$machine_id" "$timestamp" "$nonce" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('frp_mgmt_auth', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
key, machine_id, ts, nonce = sys.argv[2:6]
body = os.environ['BODY']
message = mod.signed_message(machine_id, body, ts, nonce)
sys.stdout.write(mod.sign_message(key, message))
PY
)"
  curl_err="$(mktemp)"
  if ! response="$(frp_allocator_curl \
    -X POST \
    -H 'Content-Type: application/json' \
    -H 'X-Mgmt-Auth: 1' \
    -H 'X-Mgmt-Reconcile: 1' \
    -H "X-Timestamp: ${timestamp}" \
    -H "X-Mgmt-Nonce: ${nonce}" \
    -H "X-Mgmt-Signature: ${signature}" \
    --data "$request" \
    "$allocator_url" 2>"$curl_err")"; then
    rm -f "$curl_err"
    return 0
  fi
  rm -f "$curl_err"
  mac="$(frp_identity_load_mac)" || return 0
  dropped_marker="$(
    REGISTRY_IDS="$response" STATE_PATH="$path" MGMT_MAC_KEY="$mac" python3 - <<'PY'
import hashlib,hmac,json,os,sys
from pathlib import Path
secret=os.environ['MGMT_MAC_KEY']
d=json.loads(os.environ['REGISTRY_IDS'])
if isinstance(d, dict) and d.get('error'):
    raise SystemExit(0)
received=d.pop('response_hmac',None)
canonical=json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False)
expected=hmac.new(secret.encode(),canonical.encode(),hashlib.sha256).hexdigest()
if not received or not hmac.compare_digest(received,expected):
    raise SystemExit(0)
ids=set(str(x) for x in (d.get('registry_service_ids') or []))
state=json.loads(Path(os.environ['STATE_PATH']).read_text(encoding='utf-8'))
services=state.get('services') or {}
dropped_enabled=False
for sid in list(services.keys()):
    rec=services.get(sid) or {}
    if sid not in ids:
        if rec.get('enabled', True) is not False:
            dropped_enabled=True
        services.pop(sid, None)
state['services']=services
Path(os.environ['STATE_PATH']).write_text(json.dumps(state, indent=2, sort_keys=True)+'\n', encoding='utf-8')
print('DROPPED_ENABLED=1' if dropped_enabled else 'DROPPED_ENABLED=0')
PY
  )" || return 0
  [[ "$dropped_marker" == *DROPPED_ENABLED=1* ]] && dropped=1
  frp_client_apply_reconcile_runtime "$dropped"
}

frp_enroll_services() {
  local allocator_url="$1" enroll_id="$2" enroll_secret="$3"
  local machine_id="$4" hostname_value="$5" services_file="$6"
  local allocated_file="$7" meta_file="$8"
  local auth_mode="${9:-${FRP_MGMT_AUTH:-enrollment}}"
  local request timestamp signature response curl_err nonce py key_path pubkey_pem
  local verify_rc=0
  frp_client_hook_log enroll
  if [[ "${FRP_CLIENT_HOOK_ENROLL_FAIL:-}" == "1" ]]; then
    echo "ERROR: allocator unavailable" >&2
    return 1
  fi
  if [[ -n "${FRP_CLIENT_ENROLL_COUNT_FILE:-}" ]]; then
    python3 - "$FRP_CLIENT_ENROLL_COUNT_FILE" <<'PY'
from pathlib import Path
p = Path(__import__('sys').argv[1])
n = int(p.read_text().strip() or '0') if p.is_file() else 0
p.write_text(str(n + 1) + '\n')
PY
    if [[ "${FRP_CLIENT_HOOK_COMPENSATE_FAIL:-}" == "1" ]]; then
      local enroll_n
      enroll_n="$(tr -d '\n' <"$FRP_CLIENT_ENROLL_COUNT_FILE")"
      if (( enroll_n >= 2 )); then
        echo "ERROR: compensating enrollment failed" >&2
        return 1
      fi
    fi
  fi
  pubkey_pem=""
  if [[ "$auth_mode" != identity ]]; then
    case "$(frp_identity_status)" in
      enrolled|pending)
        pubkey_pem="$(frp_identity_public_pem)" || return 1
        ;;
    esac
  fi
  request="$(python3 - "$machine_id" "$hostname_value" "$services_file" "$pubkey_pem" <<'PY'
import json, os, sys
from pathlib import Path
raw=json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
if isinstance(raw, dict) and 'services' in raw:
    services=[]
    for sid, item in raw['services'].items():
        rec=dict(item)
        rec['id']=rec.get('id') or sid
        services.append(rec)
else:
    services=raw
enabled=[]
for item in services:
    if item.get('enabled', True) is False:
        continue
    out={
        'id': item['id'],
        'name': item.get('name') or item['id'],
        'protocol': 'tcp',
        'local_ip': item['local_ip'],
        'local_port': item['local_port'],
        'preset': item.get('preset') or 'custom',
    }
    if out['preset']=='ssh':
        if item.get('ssh_user'):
            out['ssh_user']=item['ssh_user']
    enabled.append(out)
payload={
  'machine_id': sys.argv[1],
  'hostname': sys.argv[2],
  'services': enabled,
}
pub=sys.argv[4]
if pub:
    payload['mgmt_pubkey']=pub
    payload['mgmt_alg']='ecdsa-p256-sha256'
op_id=os.environ.get('FRP_CLIENT_OPERATION_ID','').strip()
if op_id:
    payload['operation_id']=op_id
print(json.dumps(payload, separators=(',', ':')))
PY
)"
  timestamp="$(date +%s)"
  py="$(frp_mgmt_auth_py)" || return 1
  curl_err="$(mktemp)"
  if [[ "$auth_mode" == identity ]]; then
    key_path="$(frp_client_identity_key_path)"
    if [[ "$(frp_identity_status)" != enrolled ]]; then
      echo "ERROR: this client does not have a usable management identity." >&2
      rm -f "$curl_err"
      return 1
    fi
    nonce="$(python3 - "$py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('frp_mgmt_auth', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.new_nonce())
PY
)"
    signature="$(BODY="$request" python3 - "$py" "$key_path" "$machine_id" "$timestamp" "$nonce" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('frp_mgmt_auth', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
key, machine_id, ts, nonce = sys.argv[2:6]
body = os.environ['BODY']
message = mod.signed_message(machine_id, body, ts, nonce)
sys.stdout.write(mod.sign_message(key, message))
PY
)"
    if ! response="$(frp_allocator_curl \
      -X POST \
      -H 'Content-Type: application/json' \
      -H 'X-Mgmt-Auth: 1' \
      -H "X-Timestamp: ${timestamp}" \
      -H "X-Mgmt-Nonce: ${nonce}" \
      -H "X-Mgmt-Signature: ${signature}" \
      --data "$request" \
      "$allocator_url" 2>"$curl_err")"; then
      frp_explain_allocator_curl_error "$curl_err"
      rm -f "$curl_err"
      return 1
    fi
    rm -f "$curl_err"
    local mac
    mac="$(frp_identity_load_mac)" || return 1
    if MGMT_MAC_KEY="$mac" RESPONSE="$response" ALLOCATED_FILE="$allocated_file" META_FILE="$meta_file" python3 - <<'PY'
import hashlib,hmac,json,os,sys
from pathlib import Path
secret=os.environ['MGMT_MAC_KEY']
d=json.loads(os.environ['RESPONSE'])
if isinstance(d, dict) and d.get('error'):
    err=str(d.get('error') or '')
    print(f'ERROR: allocator rejected the change: {err}', file=sys.stderr)
    lowered=err.lower()
    if 'revoked' in lowered or 'does not have a management identity' in lowered or 'unknown client identity' in lowered:
        raise SystemExit(2)
    raise SystemExit(1)
received=d.pop('response_hmac',None)
canonical=json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False)
expected=hmac.new(secret.encode(),canonical.encode(),hashlib.sha256).hexdigest()
if not received or not hmac.compare_digest(received,expected):
    raise SystemExit('ERROR: allocator response HMAC verification failed')
if 'ssh_port' in d or 'https_port' in d:
    raise SystemExit('ERROR: allocator returned a legacy SSH/HTTPS response')
if 'token_ciphertext' in d or 'mgmt_mac_key' in d or d.get('token'):
    raise SystemExit('ERROR: allocator returned unexpected secret material')
services=d.get('services')
if not isinstance(services, list):
    raise SystemExit('ERROR: allocator response is missing services')
transport=str(d.get('frp_transport') or 'tcp').strip().lower() or 'tcp'
if transport not in ('tcp', 'wss'):
    raise SystemExit('ERROR: allocator returned an unsupported FRP transport')
Path(os.environ['ALLOCATED_FILE']).write_text(json.dumps(services)+'\n', encoding='utf-8')
meta={
    'frp_server': str(d['frp_server']),
    'frp_server_port': str(d['frp_server_port']),
    'frp_transport': transport,
    'token_ciphertext': '',
}
alias=str(d.get('public_hostname') or '').strip()
if alias:
    meta['public_hostname']=alias
Path(os.environ['META_FILE']).write_text(json.dumps(meta)+'\n', encoding='utf-8')
PY
    then
      return 0
    else
      verify_rc=$?
      if [[ "$verify_rc" -eq 2 ]]; then
        return 2
      fi
      return 1
    fi
  fi
  signature="$(ENROLL_SECRET="$enroll_secret" TS="$timestamp" BODY="$request" python3 - <<'PY'
import hashlib,hmac,os
secret=os.environ['ENROLL_SECRET'].encode()
message=(os.environ['TS']+'\n'+os.environ['BODY']).encode()
print(hmac.new(secret,message,hashlib.sha256).hexdigest())
PY
)"
  if ! response="$(frp_allocator_curl \
    -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Enrollment-ID: ${enroll_id}" \
    -H "X-Timestamp: ${timestamp}" \
    -H "X-Signature: ${signature}" \
    --data "$request" \
    "$allocator_url" 2>"$curl_err")"; then
    frp_explain_allocator_curl_error "$curl_err"
    rm -f "$curl_err"
    return 1
  fi
  rm -f "$curl_err"
  ENROLL_SECRET="$enroll_secret" RESPONSE="$response" ALLOCATED_FILE="$allocated_file" META_FILE="$meta_file" python3 - <<'PY'
import hashlib,hmac,json,os
from pathlib import Path
secret=os.environ['ENROLL_SECRET']
d=json.loads(os.environ['RESPONSE'])
if isinstance(d, dict) and d.get('error'):
    raise SystemExit(f"ERROR: allocator rejected enrollment: {d.get('error')}")
received=d.pop('response_hmac',None)
canonical=json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False)
expected=hmac.new(secret.encode(),canonical.encode(),hashlib.sha256).hexdigest()
if not received or not hmac.compare_digest(received,expected):
    raise SystemExit('ERROR: allocator response HMAC verification failed')
if 'ssh_port' in d or 'https_port' in d:
    raise SystemExit('ERROR: allocator returned a legacy SSH/HTTPS response')
if 'mgmt_mac_key' in d:
    raise SystemExit('ERROR: allocator returned unexpected secret material')
services=d.get('services')
if not isinstance(services, list):
    raise SystemExit('ERROR: allocator response is missing services')
transport=str(d.get('frp_transport') or 'tcp').strip().lower() or 'tcp'
if transport not in ('tcp', 'wss'):
    raise SystemExit('ERROR: allocator returned an unsupported FRP transport')
Path(os.environ['ALLOCATED_FILE']).write_text(json.dumps(services)+'\n', encoding='utf-8')
token=str(d.get('token_ciphertext') or '')
if not token:
    raise SystemExit('ERROR: allocator response is missing token_ciphertext')
meta={
    'frp_server': str(d['frp_server']),
    'frp_server_port': str(d['frp_server_port']),
    'frp_transport': transport,
    'token_ciphertext': token,
    'mgmt_status': str(d.get('mgmt_status') or ''),
}
alias=str(d.get('public_hostname') or '').strip()
if alias:
    meta['public_hostname']=alias
Path(os.environ['META_FILE']).write_text(json.dumps(meta)+'\n', encoding='utf-8')
PY
  if [[ -n "$pubkey_pem" ]]; then
    frp_identity_derive_and_store_mac "$machine_id" "$enroll_secret" || return 1
  fi
}

frp_decrypt_token() {
  local ciphertext="$1" secret="$2"
  local token py
  py="$(frp_mgmt_auth_py)"
  token="$(printf '%s' "$ciphertext" | FRP_ENROLL_SECRET="$secret" python3 "$py" decrypt-token 2>/dev/null || true)"
  if [[ -z "$token" ]]; then
    echo "ERROR: failed to decrypt FRP token" >&2
    return 1
  fi
  printf '%s' "$token"
}

frp_state_diff_engine() {
  local mode="$1" current="$2" candidate="$3"
  python3 - "$mode" "$current" "$candidate" <<'PY'
import json, sys
from pathlib import Path

mode = sys.argv[1]

def svcs(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    services = data.get('services') or {}
    if isinstance(services, list):
        return {item['id']: item for item in services}, data
    return {sid: dict(item, id=item.get('id') or sid) for sid, item in services.items()}, data

def enabled(item):
    return item.get('enabled', True) is not False

def port(item):
    try:
        return int(item.get('local_port') or 0)
    except (TypeError, ValueError):
        return 0

def pair_notes(a, b):
    notes = []
    if enabled(a) and not enabled(b):
        notes.append(('runtime', 'disabled (public port remains reserved)'))
    elif (not enabled(a)) and enabled(b):
        notes.append(('runtime', 're-enabled'))
    if a.get('local_ip') != b.get('local_ip') or port(a) != port(b):
        notes.append((
            'runtime',
            f"Target: {a.get('local_ip')}:{a.get('local_port')} -> {b.get('local_ip')}:{b.get('local_port')}",
        ))
    if (a.get('name') or '') != (b.get('name') or ''):
        notes.append(('local', f"Display name: {a.get('name')} -> {b.get('name')}"))
    if a.get('preset') == 'ssh' or b.get('preset') == 'ssh':
        old_user = a.get('ssh_user') or 'legacy / unspecified'
        new_user = b.get('ssh_user') or 'legacy / unspecified'
        if old_user != new_user:
            notes.append(('local', f'SSH user: {old_user} -> {new_user}'))
    return notes

cur, cur_data = svcs(sys.argv[2])
new, _new_data = svcs(sys.argv[3])
entries = []
classes = set()
for sid in sorted(set(cur) | set(new)):
    a, b = cur.get(sid), new.get(sid)
    if a is None:
        entries.append({
            'id': sid,
            'kind': '+',
            'cls': 'runtime',
            'notes': [
                f"{b.get('local_ip')}:{b.get('local_port')}",
                'public port: assigned automatically',
            ],
        })
        classes.add('runtime')
        continue
    if b is None:
        entries.append({
            'id': sid,
            'kind': '-',
            'cls': 'runtime',
            'notes': [
                'removed from local configuration',
                'The public port remains reserved on the FRP server.',
            ],
        })
        classes.add('runtime')
        continue
    notes = pair_notes(a, b)
    if not notes:
        continue
    note_cls = 'runtime' if any(c == 'runtime' for c, _t in notes) else 'local'
    entries.append({
        'id': sid,
        'kind': '~',
        'cls': note_cls,
        'notes': [text for _c, text in notes],
    })
    classes.add(note_cls)

if 'runtime' in classes:
    overall = 'runtime'
elif 'local' in classes:
    overall = 'local'
else:
    overall = 'none'

if mode == 'class':
    print(overall)
    raise SystemExit(0)

if mode == 'pending':
    if overall == 'none':
        raise SystemExit(0)
    print('Pending changes:')
    print()
    lines = []
    for item in entries:
        lines.append(f"{item['kind']} {item['id']}")
        for note in item['notes']:
            lines.append(f'  {note}')
    print('\n'.join(lines))
    raise SystemExit(0)

print()
print('Ready to apply')
print('==============')
print()
print('Current:')
if not cur:
    print('  (none)')
else:
    for sid, item in cur.items():
        state = 'enabled' if enabled(item) else 'disabled'
        remote = item.get('remote_port')
        extra = f"    public :{remote}" if remote else '    public : assigned automatically'
        print(f"  {sid}")
        print(f"    {item.get('local_ip')}:{item.get('local_port')}")
        print(extra)
        print(f"    {state}")
print()
print('Changes:')
if not entries:
    print('  (none)')
else:
    lines = []
    for item in entries:
        lines.append(f"  {item['kind']} {item['id']}")
        for note in item['notes']:
            lines.append(f'    {note}')
    print('\n'.join(lines))
print()
if overall == 'local':
    print('These changes affect local connection information only.')
    print('The FRP server and running proxy do not need to be changed.')
elif overall == 'runtime':
    print('Applying this configuration will restart the FRP client.')
print()
PY
}

frp_state_diff() {
  frp_state_diff_engine pending "$1" "$2"
}

frp_state_change_class() {
  frp_state_diff_engine class "$1" "$2"
}

frp_state_has_diff() {
  local cls
  cls="$(frp_state_change_class "$1" "$2")"
  [[ "$cls" == none ]]
}

frp_apply_local_metadata() {
  local current="$1" candidate="$2"
  python3 - "$candidate" "$current" <<'PY'
import json, sys
from pathlib import Path
cand = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
cur = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
for key in ('allocator_url', 'frp_server', 'frp_server_port', 'frp_transport', 'hostname', 'machine_id', 'host_id', 'schema_version', 'public_hostname'):
    if key in cur and key not in cand:
        cand[key] = cur[key]
    elif key in cur:
        cand.setdefault(key, cur.get(key))
# Drop stale public_hostname when the candidate explicitly cleared it.
if 'public_hostname' in cand and not str(cand.get('public_hostname') or '').strip():
    cand.pop('public_hostname', None)
for sid, rec in (cand.get('services') or {}).items():
    prev = (cur.get('services') or {}).get(sid) or {}
    if rec.get('remote_port') in (None, '') and prev.get('remote_port') not in (None, ''):
        rec['remote_port'] = prev['remote_port']
Path(sys.argv[1]).write_text(json.dumps(cand, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
  local server access
  server="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("frp_server",""))' "$candidate")"
  access="$(frp_client_access_path)"
  local tmp_access
  tmp_access="$(mktemp)"
  render_access_info "$tmp_access" "$server" "$candidate"
  frp_backup_client_files >/dev/null
  frp_atomic_write_json_file "$(frp_client_state_path)" "$candidate" 0600
  frp_state_has_secrets "$(frp_client_state_path)" || {
    echo "ERROR: client-state.json must not contain secrets" >&2
    rm -f "$tmp_access"
    return 1
  }
  frp_atomic_copy_file "$access" "$tmp_access" 0644
  rm -f "$tmp_access"
  echo "Applied local changes."
  echo "Allocator contacted : NO"
  echo "frpc restarted      : NO"
}

frp_merge_ports_into_state() {
  python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
state_path, alloc_path = Path(sys.argv[1]), Path(sys.argv[2])
state = json.loads(state_path.read_text(encoding='utf-8'))
allocated = json.loads(alloc_path.read_text(encoding='utf-8'))
by_id = {str(item['id']): int(item['remote_port']) for item in allocated}
services = state['services']
enabled_ids = [sid for sid, rec in services.items() if rec.get('enabled', True) is not False]
if set(by_id) != set(enabled_ids):
    raise SystemExit('ERROR: allocator did not return every requested enabled service')
for sid, rec in services.items():
    if rec.get('enabled', True) is False:
        continue
    rec['remote_port'] = by_id[sid]
state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY
}

frp_backup_client_files() {
  local stamp dest src
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dest="$(frp_client_backup_dir)/${stamp}"
  mkdir -p "$dest"
  chmod 700 "$(frp_client_backup_dir)" 2>/dev/null || true
  chmod 700 "$dest"
  for src in "$(frp_client_state_path)" "$(frp_client_toml_path)" "$(frp_client_access_path)"; do
    if [[ -f "$src" ]]; then
      install -m 0600 "$src" "$dest/$(basename "$src")"
    fi
  done
  printf '%s' "$dest"
  python3 - "$(frp_client_backup_dir)" "$FRP_CLIENT_BACKUP_KEEP" <<'PY'
import shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
keep = int(sys.argv[2])
if not root.is_dir():
    raise SystemExit(0)
dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
for extra in dirs[: max(0, len(dirs) - keep)]:
    shutil.rmtree(extra, ignore_errors=True)
PY
}

frp_restore_client_files() {
  local backup="$1"
  [[ -d "$backup" ]] || return 1
  local f dest mode
  for f in client-state.json frpc.toml access-info.txt; do
    if [[ -f "$backup/$f" ]]; then
      case "$f" in
        client-state.json) dest="$(frp_client_state_path)"; mode=0600 ;;
        frpc.toml) dest="$(frp_client_toml_path)"; mode=0600 ;;
        access-info.txt) dest="$(frp_client_access_path)"; mode=0644 ;;
      esac
      frp_atomic_copy_file "$dest" "$backup/$f" "$mode"
    fi
  done
}

frp_lock_pid_alive() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

frp_acquire_client_lock() {
  local lock pid
  lock="$(frp_client_lock_dir)"
  mkdir -p "$(dirname "$lock")"
  if [[ -d "$lock" ]]; then
    pid="$(tr -d '\n' <"$lock/pid" 2>/dev/null || true)"
    if frp_lock_pid_alive "$pid"; then
      echo "ERROR: another frp-client management operation is already running." >&2
      return 1
    fi
    rm -rf "$lock"
  fi
  if [[ -f "$lock" ]]; then
    pid=""
    if [[ -f "${lock}.pid" ]]; then
      pid="$(tr -d '\n' <"${lock}.pid")"
    fi
    if frp_lock_pid_alive "$pid" && ! command -v flock >/dev/null 2>&1; then
      echo "ERROR: another frp-client management operation is already running." >&2
      return 1
    fi
    if [[ -z "${FRP_CLIENT_LOCK_FD:-}" ]] && ! command -v flock >/dev/null 2>&1; then
      if ! frp_lock_pid_alive "$pid"; then
        rm -f "$lock" "${lock}.pid"
      fi
    fi
  fi
  if command -v flock >/dev/null 2>&1; then
    if [[ -z "${FRP_CLIENT_LOCK_FD:-}" ]]; then
      exec {FRP_CLIENT_LOCK_FD}>>"$lock"
    fi
    if ! flock -n "$FRP_CLIENT_LOCK_FD"; then
      echo "ERROR: another frp-client management operation is already running." >&2
      exec {FRP_CLIENT_LOCK_FD}>&-
      unset FRP_CLIENT_LOCK_FD
      return 1
    fi
    printf '%s\n' "$$" >"${lock}.pid"
    chmod 600 "$lock" 2>/dev/null || true
    return 0
  fi
  if ! mkdir "$lock" 2>/dev/null; then
    pid="$(tr -d '\n' <"$lock/pid" 2>/dev/null || true)"
    if frp_lock_pid_alive "$pid"; then
      echo "ERROR: another frp-client management operation is already running." >&2
      return 1
    fi
    rm -rf "$lock"
    if ! mkdir "$lock" 2>/dev/null; then
      echo "ERROR: another frp-client management operation is already running." >&2
      return 1
    fi
  fi
  printf '%s\n' "$$" >"$lock/pid"
  chmod 700 "$lock" 2>/dev/null || true
}

frp_release_client_lock() {
  local lock
  lock="$(frp_client_lock_dir)"
  if [[ -n "${FRP_CLIENT_LOCK_FD:-}" ]]; then
    flock -u "$FRP_CLIENT_LOCK_FD" 2>/dev/null || true
    exec {FRP_CLIENT_LOCK_FD}>&- 2>/dev/null || true
    unset FRP_CLIENT_LOCK_FD
    rm -f "${lock}.pid"
  fi
  if [[ -d "$lock" ]]; then
    rm -rf "$lock"
  fi
}

frp_sha256_file() {
  python3 - "$1" <<'PY'
import hashlib, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    sys.stdout.write('')
else:
    sys.stdout.write(hashlib.sha256(p.read_bytes()).hexdigest())
PY
}

frp_pending_write() {
  local phase="$1" op_id="$2" server_outcome="${3:-pending}"
  local dest current candidate
  dest="$(frp_client_pending_path)"
  current="$(frp_client_state_path)"
  candidate="${CANDIDATE_FILE:-}"
  python3 - "$dest" "$phase" "$op_id" "$server_outcome" "$current" "$candidate" <<'PY'
import json, os, sys, tempfile, time
from pathlib import Path
dest = Path(sys.argv[1])
phase, op_id, server_outcome = sys.argv[2:5]
current, candidate = Path(sys.argv[5]), Path(sys.argv[6]) if sys.argv[6] else None

def sha(path):
    if not path or not path.is_file():
        return ''
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()

service_ids = []
if candidate and candidate.is_file():
    try:
        data = json.loads(candidate.read_text(encoding='utf-8'))
        service_ids = sorted((data.get('services') or {}).keys())
    except Exception:
        service_ids = []
marker = {
    'schema_version': 1,
    'operation_id': op_id,
    'phase': phase,
    'server_mutation': server_outcome,
    'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'service_ids': service_ids,
    'prior_state_sha256': sha(current),
    'candidate_state_sha256': sha(candidate) if candidate else '',
}
dest.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=dest.name + '.', suffix='.tmp', dir=str(dest.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(marker, fh, indent=2, sort_keys=True)
        fh.write('\n')
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
finally:
    if os.path.exists(tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
PY
}

frp_pending_clear() {
  rm -f "$(frp_client_pending_path)"
}

frp_latest_backup_dir() {
  python3 - "$(frp_client_backup_dir)" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
if not root.is_dir():
    raise SystemExit(0)
dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
if not dirs:
    raise SystemExit(0)
sys.stdout.write(str(dirs[-1]))
PY
}

frp_token_from_toml_file() {
  python3 - "$1" <<'PY'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(1)
text = path.read_text(encoding='utf-8')
for line in text.splitlines():
    m = re.match(r'^\s*auth\.token\s*=\s*"(.*)"\s*$', line)
    if m:
        sys.stdout.write(m.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

frp_regenerate_access_from_state() {
  local state server
  state="$(frp_client_state_path)"
  [[ -f "$state" ]] || return 1
  frp_load_client_state "$state" || return 1
  server="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("frp_server",""))' "$state")"
  render_access_info "$(frp_client_access_path)" "$server" "$state"
}

frp_regenerate_toml_from_state() {
  local state token server port host_id enabled_list
  state="$(frp_client_state_path)"
  [[ -f "$state" ]] || return 1
  frp_load_client_state "$state" || return 1
  token="$1"
  [[ -n "$token" ]] || return 1
  server="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["frp_server"])' "$state")"
  port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["frp_server_port"])' "$state")"
  host_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["host_id"])' "$state")"
  transport="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1],encoding="utf-8")).get("frp_transport") or "tcp"))' "$state")"
  enabled_list="$(mktemp)"
  frp_enabled_services_list "$state" >"$enabled_list"
  if ! render_frpc_toml "$(frp_client_toml_path)" "$server" "$port" "$token" "$host_id" "$enabled_list" "$transport"; then
    rm -f "$enabled_list"
    return 1
  fi
  rm -f "$enabled_list"
  return 0
}

frp_artifacts_consistent() {
  python3 - "$(frp_client_state_path)" "$(frp_client_toml_path)" "$(frp_client_access_path)" <<'PY'
import json, re, sys
from pathlib import Path
state_p, toml_p, access_p = (Path(a) for a in sys.argv[1:4])
if not state_p.is_file():
    raise SystemExit(2)
try:
    data = json.loads(state_p.read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(2)
if not isinstance(data, dict) or data.get('schema_version') != 1:
    raise SystemExit(2)
services = data.get('services') or {}
if not isinstance(services, dict):
    raise SystemExit(2)
toml_text = toml_p.read_text(encoding='utf-8') if toml_p.is_file() else ''
missing_toml = not toml_p.is_file()
missing_access = not access_p.is_file()
enabled = []
for sid, rec in services.items():
    if rec.get('enabled', True) is False:
        continue
    enabled.append(str(rec.get('id') or sid))
missing_proxy = False
for sid in enabled:
    if f'-{sid}"' not in toml_text and f'-{sid}' not in toml_text:
        missing_proxy = True
        break
if missing_toml or missing_access or missing_proxy:
    raise SystemExit(1)
raise SystemExit(0)
PY
}

frp_lifecycle_recover() {
  local state toml access pending backup token rc=0
  state="$(frp_client_state_path)"
  toml="$(frp_client_toml_path)"
  access="$(frp_client_access_path)"
  pending="$(frp_client_pending_path)"
  if [[ ! -f "$state" ]]; then
    return 0
  fi
  if ! frp_load_client_state "$state" 2>/dev/null; then
    echo "ERROR: client-state.json is unreadable." >&2
    frp_emit_failure_class REGISTRY_INVALID
    return 1
  fi
  if [[ ! -f "$access" ]]; then
    if frp_regenerate_access_from_state; then
      echo "Regenerated missing access-info.txt from local client state."
    else
      echo "ERROR: access-info.txt is missing and could not be regenerated." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 2
    fi
  fi
  if [[ ! -f "$toml" ]]; then
    token=""
    backup="$(frp_latest_backup_dir || true)"
    if [[ -n "$backup" && -f "$backup/frpc.toml" ]]; then
      token="$(frp_token_from_toml_file "$backup/frpc.toml" || true)"
    fi
    if [[ -z "$token" ]]; then
      echo "ERROR: frpc.toml is missing and the FRP token is not available from backups." >&2
      echo "RECOVERY_REQUIRED: restore frpc.toml from backup or re-enroll this client." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 2
    fi
    if frp_regenerate_toml_from_state "$token"; then
      echo "Regenerated missing frpc.toml from local client state."
    else
      echo "ERROR: frpc.toml is missing and could not be regenerated." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 2
    fi
  fi
  if ! frp_artifacts_consistent; then
    token="$(frp_read_existing_token 2>/dev/null || true)"
    if [[ -z "$token" ]]; then
      backup="$(frp_latest_backup_dir || true)"
      if [[ -n "$backup" && -f "$backup/frpc.toml" ]]; then
        token="$(frp_token_from_toml_file "$backup/frpc.toml" || true)"
      fi
    fi
    if [[ -n "$token" ]] && frp_regenerate_toml_from_state "$token" && frp_regenerate_access_from_state; then
      echo "Repaired local runtime artifacts from client-state.json."
    else
      echo "ERROR: local client artifacts are inconsistent." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 2
    fi
  fi
  if [[ -f "$pending" ]]; then
    if frp_artifacts_consistent; then
      frp_pending_clear
    else
      echo "ERROR: an Apply was interrupted and local state needs recovery." >&2
      echo "RECOVERY_REQUIRED: run frp-client apply with the desired configuration." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 2
    fi
  fi
  return 0
}

frp_lifecycle_report() {
  local pending
  pending="$(frp_client_pending_path)"
  if [[ -f "$pending" ]]; then
    echo "Lifecycle        : RECOVERY_REQUIRED"
    python3 - "$pending" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
except Exception:
    raise SystemExit(0)
phase = data.get('phase') or 'unknown'
op = data.get('operation_id') or ''
print(f"Pending apply    : phase={phase} operation_id={op}")
PY
    return 0
  fi
  if frp_artifacts_consistent; then
    echo "Lifecycle        : consistent"
  else
    echo "Lifecycle        : RECOVERY_REQUIRED"
  fi
}

frp_client_verify_config() {
  local cfg="$1"
  frp_client_hook_log verify
  if [[ "${FRP_CLIENT_HOOK_VERIFY_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated frpc verify failure" >&2
    return 1
  fi
  local frpc_bin
  frpc_bin="$(frp_client_path /usr/local/bin/frpc)"
  if [[ -x "$frpc_bin" ]]; then
    "$frpc_bin" verify -c "$cfg"
  elif command -v frpc >/dev/null 2>&1; then
    frpc verify -c "$cfg"
  else
    echo "ERROR: frpc is not available to verify the generated config" >&2
    return 1
  fi
}

frp_client_restart() {
  frp_client_hook_log restart
  if [[ "${FRP_CLIENT_HOOK_RESTART_FAIL:-}" == "1" ]]; then
    FRP_CLIENT_HOOK_RESTART_FAIL=0
    echo "ERROR: simulated service restart failure" >&2
    return 1
  fi
  if [[ "${FRP_SKIP_SYSTEMD:-}" == "1" || -n "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    return 0
  fi
  if frp_is_darwin; then
    frp_macos_launchd_set_enabled enable
    if frp_macos_launchd_running; then
      frp_macos_launchd_kickstart
    else
      frp_macos_launchd_bootstrap
    fi
  else
    systemctl enable frpc >/dev/null && systemctl restart frpc
  fi
}

frp_client_service_status() {
  if [[ "${FRP_SKIP_SYSTEMD:-}" == "1" || -n "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    printf 'test'
  elif frp_is_darwin; then
    frp_macos_launchd_running && printf 'active' || printf 'inactive'
  else
    systemctl is-active frpc 2>/dev/null || printf 'unknown'
  fi
}

frp_client_wait_proxies() {
  frp_client_hook_log proxies
  if [[ "${FRP_CLIENT_HOOK_PROXY_FAIL:-}" == "1" ]]; then
    echo "ERROR: frpc did not register every requested proxy successfully" >&2
    return 1
  fi
  if [[ "${FRP_SKIP_SYSTEMD:-}" == "1" || -n "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    return 0
  fi
  wait_for_proxies "$@"
}

frp_print_state_services() {
  python3 - "$1" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
server = data.get('frp_server', '')
services = data.get('services') or {}
if not services:
    print('(none)')
    raise SystemExit(0)
n = 0
for sid, item in services.items():
    n += 1
    enabled = item.get('enabled', True) is not False
    state = 'enabled' if enabled else 'disabled'
    print(f"{n}. {item.get('id') or sid}")
    preset = item.get('preset') or 'custom'
    labels = {'ssh': 'SSH / TCP', 'http': 'HTTP / TCP', 'https': 'HTTPS / TCP'}
    print(f"   Type        : {labels.get(preset, 'Custom TCP')}")
    print(f"   Target      : {item.get('local_ip')}:{item.get('local_port')}")
    remote = item.get('remote_port')
    if remote:
        print(f"   Public port : {remote}")
    print(f"   State       : {state}")
    print()
PY
}

# --- Project-layer client upgrade (does not re-enroll) --------------------

frp_client_atomic_install() {
  local src="$1" dest="$2" mode="${3:-0755}"
  local dir tmp
  if declare -F frp_require_safe_write_path >/dev/null 2>&1; then
    frp_require_safe_write_path "$dest" || return 1
  fi
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.frp-upgrade.XXXXXX")"
  cp "$src" "$tmp"
  chmod "$mode" "$tmp"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
}

frp_client_digest() {
  local file="$1"
  python3 - "$file" <<'PY'
import hashlib, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    sys.stdout.write("")
else:
    sys.stdout.write(hashlib.sha256(p.read_bytes()).hexdigest())
PY
}

frp_client_upgrade_source_version() {
  local source="$1"
  if [[ -f "${source}/VERSION" ]]; then
    # shellcheck disable=SC1091
    . "${source}/VERSION"
  fi
}

frp_client_install_management_files() {
  local source="$1"
  local libdir bindir
  libdir="$(frp_client_lib_dir)"
  bindir="$(frp_client_path /usr/local/bin)"
  mkdir -p "$libdir" "$bindir"
  [[ -f "${source}/lib/frp-client-common.sh" ]] || {
    echo "ERROR: missing ${source}/lib/frp-client-common.sh" >&2
    return 1
  }
  [[ -f "${source}/lib/frp-common.sh" ]] || {
    echo "ERROR: missing ${source}/lib/frp-common.sh" >&2
    return 1
  }
  [[ -f "${source}/lib/frp-macos.sh" ]] || {
    echo "ERROR: missing ${source}/lib/frp-macos.sh" >&2
    return 1
  }
  [[ -f "${source}/lib/frp_mgmt_auth.py" ]] || {
    echo "ERROR: missing ${source}/lib/frp_mgmt_auth.py" >&2
    return 1
  }
  [[ -f "${source}/lib/frp-doctor-common.sh" ]] || {
    echo "ERROR: missing ${source}/lib/frp-doctor-common.sh" >&2
    return 1
  }
  [[ -f "${source}/lib/frp_doctor.py" ]] || {
    echo "ERROR: missing ${source}/lib/frp_doctor.py" >&2
    return 1
  }
  [[ -f "${source}/lib/frp_ctl_grammar.py" ]] || {
    echo "ERROR: missing ${source}/lib/frp_ctl_grammar.py" >&2
    return 1
  }
  [[ -f "${source}/lib/frp_ctl_repl.py" ]] || {
    echo "ERROR: missing ${source}/lib/frp_ctl_repl.py" >&2
    return 1
  }
  [[ -f "${source}/tools/frp-client" ]] || {
    echo "ERROR: missing ${source}/tools/frp-client" >&2
    return 1
  }
  [[ -f "${source}/tools/frpctl" ]] || {
    echo "ERROR: missing ${source}/tools/frpctl" >&2
    return 1
  }
  install -m 0644 "${source}/lib/frp-client-common.sh" "${libdir}/frp-client-common.sh"
  install -m 0644 "${source}/lib/frp-common.sh" "${libdir}/frp-common.sh"
  install -m 0644 "${source}/lib/frp-macos.sh" "${libdir}/frp-macos.sh"
  install -m 0644 "${source}/lib/frp_mgmt_auth.py" "${libdir}/frp_mgmt_auth.py"
  install -m 0644 "${source}/lib/frp-doctor-common.sh" "${libdir}/frp-doctor-common.sh"
  install -m 0644 "${source}/lib/frp_doctor.py" "${libdir}/frp_doctor.py"
  install -m 0644 "${source}/lib/frp_ctl_grammar.py" "${libdir}/frp_ctl_grammar.py"
  install -m 0644 "${source}/lib/frp_ctl_repl.py" "${libdir}/frp_ctl_repl.py"
  install -m 0755 "${source}/tools/frp-client" "${bindir}/frp-client"
  install -m 0755 "${source}/tools/frpctl" "${bindir}/frpctl"
  if [[ -f "${source}/client/${FRP_MACOS_LAUNCHD_LABEL}.plist" ]]; then
    install -m 0644 "${source}/client/${FRP_MACOS_LAUNCHD_LABEL}.plist" \
      "${libdir}/${FRP_MACOS_LAUNCHD_LABEL}.plist"
  fi
  frp_client_upgrade_source_version "$source"
  frp_client_write_version_file
}

frp_client_upgrade_destinations() {
  # dest_rel:mode:source_rel
  printf '%s\n' \
    "usr/local/lib/frp-auto-deploy/frp-client-common.sh:0644:lib/frp-client-common.sh" \
    "usr/local/lib/frp-auto-deploy/frp-common.sh:0644:lib/frp-common.sh" \
    "usr/local/lib/frp-auto-deploy/frp-macos.sh:0644:lib/frp-macos.sh" \
    "usr/local/lib/frp-auto-deploy/com.datarelay.frp-auto-deploy.frpc.plist:0644:client/com.datarelay.frp-auto-deploy.frpc.plist" \
    "usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py:0644:lib/frp_mgmt_auth.py" \
    "usr/local/lib/frp-auto-deploy/frp-doctor-common.sh:0644:lib/frp-doctor-common.sh" \
    "usr/local/lib/frp-auto-deploy/frp_doctor.py:0644:lib/frp_doctor.py" \
    "usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py:0644:lib/frp_ctl_grammar.py" \
    "usr/local/lib/frp-auto-deploy/frp_ctl_repl.py:0644:lib/frp_ctl_repl.py" \
    "usr/local/lib/frp-auto-deploy/frp-role-ownership.sh:0644:lib/frp-role-ownership.sh" \
    "usr/local/bin/frp-client:0755:tools/frp-client" \
    "usr/local/bin/frpctl:0755:tools/frpctl"
}

frp_client_upgrade_validate_existing() {
  local state toml ident
  state="$(frp_client_state_path)"
  toml="$(frp_client_toml_path)"
  [[ -f "$state" ]] || {
    echo "ERROR: no existing FRP client installation was found." >&2
    echo "Use the client bootstrap installer to enroll a new client." >&2
    return 1
  }
  frp_load_client_state "$state" || return 1
  if [[ -f "$toml" ]]; then
    frp_client_verify_config "$toml" || return 1
  fi
  ident="$(frp_identity_status)"
  if [[ "$ident" == corrupt ]]; then
    echo "WARNING: this client's management identity is unusable." >&2
    echo "Software upgrade will continue without regenerating identity files." >&2
  fi
  return 0
}

frp_client_require_server_compatible_for_upgrade() {
  # Supported mixed-version policy: upgrade server first, then clients.
  # Client candidate must not be newer than the live server project_version.
  local state allocator_url origin health resp server_ver candidate_ver ca
  state="$(frp_client_state_path)"
  [[ -f "$state" ]] || return 0
  allocator_url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("allocator_url") or "")' "$state" 2>/dev/null || true)"
  [[ -n "$allocator_url" ]] || return 0
  origin="$(frp_allocator_origin_url "$allocator_url" 2>/dev/null)" || return 0
  health="${origin}/healthz"
  resp=""
  ca="$(frp_client_path /etc/frp-auto-deploy/allocator-ca.crt)"
  if [[ ! -f "$ca" ]]; then
    ca="$(frp_client_path /etc/frp/allocator-ca.crt)"
  fi
  if [[ -f "$ca" ]]; then
    resp="$(python3 - "$health" "$ca" <<'PY' 2>/dev/null || true
import ssl, sys, urllib.request
url, ca = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=ca)
with urllib.request.urlopen(url, context=ctx, timeout=5) as handle:
    sys.stdout.write(handle.read().decode("utf-8", "replace"))
PY
)"
  fi
  [[ -n "$resp" ]] || return 0
  server_ver="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("project_version") or "")' "$resp" 2>/dev/null || true)"
  candidate_ver="${1:-}"
  [[ -n "$server_ver" && -n "$candidate_ver" ]] || return 0
  if python3 - "$server_ver" "$candidate_ver" <<'PY'
import sys
def parse(text):
    parts = []
    for piece in str(text).split('.'):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    return tuple(parts) if parts else None
server = parse(sys.argv[1])
candidate = parse(sys.argv[2])
if server is None or candidate is None:
    raise SystemExit(0)
raise SystemExit(0 if candidate <= server else 1)
PY
  then
    return 0
  fi
  echo "ERROR: SERVER_VERSION_TOO_OLD" >&2
  echo "Server project version ${server_ver} is older than client candidate ${candidate_ver}." >&2
  echo "Upgrade the server first, then upgrade clients." >&2
  frp_emit_failure_class SERVER_VERSION_TOO_OLD
  return 1
}

frp_client_upgrade_validate_staged() {
  local staged="$1" rel mode src dest
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    dest="${staged}/${rel}"
    [[ -f "$dest" ]] || {
      echo "ERROR: staged update is missing ${rel}" >&2
      return 1
    }
  done < <(frp_client_upgrade_destinations)
  bash -n "${staged}/usr/local/bin/frp-client" || return 1
  bash -n "${staged}/usr/local/bin/frpctl" || return 1
  bash -n "${staged}/usr/local/lib/frp-auto-deploy/frp-client-common.sh" || return 1
  bash -n "${staged}/usr/local/lib/frp-auto-deploy/frp-common.sh" || return 1
  bash -n "${staged}/usr/local/lib/frp-auto-deploy/frp-doctor-common.sh" || return 1
  python3 -m py_compile "${staged}/usr/local/lib/frp-auto-deploy/frp_mgmt_auth.py" || return 1
  python3 -m py_compile "${staged}/usr/local/lib/frp-auto-deploy/frp_doctor.py" || return 1
  python3 -m py_compile "${staged}/usr/local/lib/frp-auto-deploy/frp_ctl_grammar.py" || return 1
  python3 -m py_compile "${staged}/usr/local/lib/frp-auto-deploy/frp_ctl_repl.py" || return 1
  rm -rf "${staged}/usr/local/lib/frp-auto-deploy/__pycache__" \
    "${staged}/usr/local/lib/frp-auto-deploy/"*.pyc 2>/dev/null || true
  [[ -x "${staged}/usr/local/bin/frp-client" ]] || {
    echo "ERROR: staged frp-client is not executable" >&2
    return 1
  }
  [[ -x "${staged}/usr/local/bin/frpctl" ]] || {
    echo "ERROR: staged frpctl is not executable" >&2
    return 1
  }
  if [[ "${FRP_CLIENT_UPGRADE_HOOK_FAIL:-}" == "validate" ]]; then
    echo "ERROR: simulated staged update validation failure" >&2
    return 1
  fi
  return 0
}

frp_client_upgrade_backup_tools() {
  local stamp dest live rel mode src base
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dest="$(frp_client_upgrade_backup_root)/${stamp}"
  mkdir -p "$dest"
  chmod 700 "$(frp_client_upgrade_backup_root)" 2>/dev/null || true
  chmod 700 "$dest"
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    live="$(frp_client_path "/${rel}")"
    base="$(basename "$rel")"
    if [[ -f "$live" ]]; then
      install -m "$mode" "$live" "${dest}/${base}"
      printf 'present %s\n' "$base" >>"${dest}/manifest"
    else
      printf 'absent %s\n' "$base" >>"${dest}/manifest"
    fi
  done < <(frp_client_upgrade_destinations)
  live="$(frp_client_version_file)"
  if [[ -f "$live" ]]; then
    install -m 0644 "$live" "${dest}/version"
    printf 'present version\n' >>"${dest}/manifest"
  else
    printf 'absent version\n' >>"${dest}/manifest"
  fi
  python3 - "$(frp_client_upgrade_backup_root)" "$FRP_CLIENT_UPGRADE_BACKUP_KEEP" <<'PY'
import shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
keep = int(sys.argv[2])
if not root.is_dir():
    raise SystemExit(0)
dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
for extra in dirs[: max(0, len(dirs) - keep)]:
    shutil.rmtree(extra, ignore_errors=True)
PY
  printf '%s' "$dest"
}

frp_client_upgrade_restore_tools() {
  local backup="$1" live rel mode src base
  [[ -d "$backup" ]] || return 1
  if [[ "${FRP_CLIENT_UPGRADE_HOOK_ROLLBACK_FAIL:-}" == "1" ]]; then
    echo "ERROR: simulated update rollback failure" >&2
    return 1
  fi
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    live="$(frp_client_path "/${rel}")"
    base="$(basename "$rel")"
    if [[ -f "${backup}/${base}" ]]; then
      install -m "$mode" "${backup}/${base}" "$live"
    else
      rm -f "$live"
    fi
  done < <(frp_client_upgrade_destinations)
  live="$(frp_client_version_file)"
  if [[ -f "${backup}/version" ]]; then
    mkdir -p "$(dirname "$live")"
    install -m 0644 "${backup}/version" "$live"
  else
    rm -f "$live"
  fi
  return 0
}

frp_client_upgrade_verify_restored() {
  local backup="$1" live rel mode src base state
  [[ -f "${backup}/manifest" ]] || return 1
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    live="$(frp_client_path "/${rel}")"
    base="$(basename "$rel")"
    state="$(awk -v b="$base" '$2==b {print $1; exit}' "${backup}/manifest")"
    case "$state" in
      present)
        [[ -f "$live" && "$(frp_client_digest "$live")" == "$(frp_client_digest "${backup}/${base}")" ]] \
          || return 1
        ;;
      absent)
        [[ ! -e "$live" ]] || return 1
        ;;
      *)
        return 1
        ;;
    esac
  done < <(frp_client_upgrade_destinations)
  live="$(frp_client_version_file)"
  state="$(awk '$2=="version" {print $1; exit}' "${backup}/manifest")"
  case "$state" in
    present)
      [[ -f "$live" && "$(frp_client_digest "$live")" == "$(frp_client_digest "${backup}/version")" ]] \
        || return 1
      ;;
    absent)
      [[ ! -e "$live" ]] || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

frp_client_upgrade_post_mutation_guard() {
  [[ "${FRP_CLIENT_UPGRADE_HOOK_FAIL:-}" == "unbound-after-install" ]] || return 0
  echo "ERROR: simulated unexpected post-mutation abort" >&2
  return 1
}

_frp_client_upgrade_err() {
  local ec=$?
  if [[ "${_FRP_CLIENT_UPGRADE_MUTATION_STARTED:-0}" == "1" && \
        "${_FRP_CLIENT_UPGRADE_IN_ROLLBACK:-0}" != "1" && \
        "${_FRP_CLIENT_UPGRADE_ROLLBACK_DONE:-0}" != "1" && \
        -n "${_FRP_CLIENT_UPGRADE_BACKUP:-}" ]]; then
    frp_client_upgrade_rollback "$_FRP_CLIENT_UPGRADE_BACKUP" FILE_COMMIT_FAILED || true
  fi
  return "$ec"
}

frp_client_upgrade_rollback() {
  local backup="$1" failure_class="${2:-FILE_COMMIT_FAILED}"
  if [[ "${_FRP_CLIENT_UPGRADE_ROLLBACK_DONE:-0}" == "1" ]]; then
    return "${_FRP_CLIENT_UPGRADE_ROLLBACK_RC:-1}"
  fi
  if [[ "${_FRP_CLIENT_UPGRADE_IN_ROLLBACK:-0}" == "1" ]]; then
    return 1
  fi
  _FRP_CLIENT_UPGRADE_IN_ROLLBACK=1
  if frp_client_upgrade_restore_tools "$backup" \
    && frp_client_upgrade_verify_restored "$backup"; then
    echo "UPGRADE_ROLLBACK=PASS"
    frp_emit_failure_class "$failure_class"
    frp_txn_clear client
    _FRP_CLIENT_UPGRADE_ROLLBACK_RC=0
    _FRP_CLIENT_UPGRADE_ROLLBACK_DONE=1
    _FRP_CLIENT_UPGRADE_IN_ROLLBACK=0
    return 0
  fi
  echo "UPGRADE_ROLLBACK=FAIL"
  frp_emit_failure_class UPDATE_ROLLBACK_FAILED
  echo "RECOVERY_REQUIRED" >&2
  echo "PENDING_MARKER_CLEARED=NO"
  _FRP_CLIENT_UPGRADE_ROLLBACK_RC=1
  _FRP_CLIENT_UPGRADE_ROLLBACK_DONE=1
  _FRP_CLIENT_UPGRADE_IN_ROLLBACK=0
  return 1
}

frp_client_upgrade_stage() {
  local source="$1" staged="$2" rel mode src
  mkdir -p "$staged"
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    [[ -f "${source}/${src}" ]] || {
      echo "ERROR: update source is missing ${src}" >&2
      return 1
    }
    mkdir -p "$(dirname "${staged}/${rel}")"
    install -m "$mode" "${source}/${src}" "${staged}/${rel}"
  done < <(frp_client_upgrade_destinations)
}

frp_client_upgrade_install_staged() {
  local staged="$1" live rel mode src
  local replaced=0
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    live="$(frp_client_path "/${rel}")"
    frp_client_atomic_install "${staged}/${rel}" "$live" "$mode" || return 1
    replaced=$((replaced + 1))
    if [[ "$replaced" -eq 1 && "${FRP_CLIENT_UPGRADE_HOOK_FAIL:-}" == "install" ]]; then
      echo "ERROR: simulated tool install failure" >&2
      return 1
    fi
  done < <(frp_client_upgrade_destinations)
  return 0
}

frp_client_upgrade_verify() {
  local ident_before="$1"
  local live rel mode src
  while IFS=: read -r rel mode src; do
    [[ -n "$rel" ]] || continue
    live="$(frp_client_path "/${rel}")"
    [[ -f "$live" ]] || {
      echo "ERROR: upgraded file missing: ${live}" >&2
      return 1
    }
  done < <(frp_client_upgrade_destinations)
  [[ -x "$(frp_client_path /usr/local/bin/frp-client)" ]] || return 1
  [[ -x "$(frp_client_path /usr/local/bin/frpctl)" ]] || return 1
  frp_load_client_state "$(frp_client_state_path)" || return 1
  if [[ -f "$(frp_client_toml_path)" ]]; then
    frp_client_verify_config "$(frp_client_toml_path)" || return 1
  fi
  if [[ "$ident_before" == enrolled && "$(frp_identity_status)" != enrolled ]]; then
    echo "ERROR: management identity was not preserved" >&2
    return 1
  fi
  if [[ "${FRP_CLIENT_UPGRADE_HOOK_FAIL:-}" == "verify" ]]; then
    echo "ERROR: simulated post-upgrade verification failure" >&2
    return 1
  fi
  return 0
}

frp_client_apply_upgrade() {
  local source="${1:-}"
  local check_only="${2:-0}"
  local previous target staged backup ident_before ident_after
  local installed_bundle target_bundle update_needed=1
  local state_before toml_before access_before key_before pub_before mac_before
  local frp_before frp_after

  if [[ -z "$source" || ! -d "$source" ]]; then
    echo "ERROR: update source directory is required" >&2
    return 1
  fi
  if [[ ${EUID} -ne 0 && -z "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    echo "ERROR: run with sudo" >&2
    return 1
  fi

  # Serialize against apply/sync/frp-update and other client mutations.
  frp_acquire_client_lock || return 1
  _frp_client_upgrade_release_lock() { frp_release_client_lock; }
  # shellcheck disable=SC2064
  trap '_frp_client_upgrade_release_lock' RETURN

  local kind="${_FRP_CLIENT_UPDATE_KIND:-bundle}"
  local candidate_meta candidate_channel="unknown" candidate_ref="unknown"
  local installed_channel installed_ref expected_channel="" expected_ref=""
  local target_channel_out target_ref_out target_bundle_out

  _FRP_CLIENT_UPGRADE_ROLLBACK_DONE=0
  _FRP_CLIENT_UPGRADE_ROLLBACK_RC=0
  _FRP_CLIENT_UPGRADE_IN_ROLLBACK=0
  _FRP_CLIENT_UPGRADE_MUTATION_STARTED=0
  _FRP_CLIENT_UPGRADE_SET_E=0
  # Client upgrade owns the client transaction marker only.
  FRP_TXN_ROLE=client
  export FRP_TXN_ROLE
  frp_client_upgrade_validate_existing || return 1
  frp_txn_adopt_legacy_marker client || return 1
  if [[ -f "$(frp_txn_marker_path client)" ]]; then
    echo "A previous software update was interrupted."
    local recovered=""
    recovered="$(frp_txn_field snapshot_path)"
    if [[ -z "$recovered" || ! -d "$recovered" ]]; then
      echo "ERROR: pending client update does not name a usable snapshot; refusing to guess the newest backup." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 1
    fi
    if ! frp_client_upgrade_restore_tools "$recovered" || ! frp_client_upgrade_verify_restored "$recovered"; then
      echo "ERROR: interrupted update could not be rolled back automatically." >&2
      frp_emit_failure_class RECOVERY_REQUIRED
      return 1
    fi
    echo "Restored the previous management files from backup."
    frp_txn_clear client
  fi

  previous="$(frp_client_installed_project_version)"
  installed_bundle="$(frp_client_installed_bundle_sha256)"
  installed_channel="$(frp_client_installed_release_channel)"
  installed_ref="$(frp_client_installed_source_ref)"
  target_bundle="$(frp_client_external_bundle_sha256)"
  expected_channel="$(frp_client_explicit_expected_channel || true)"
  expected_ref="${FRP_EXPECTED_SOURCE_REF:-}"
  frp_before="$(frp_client_installed_frp_version)"
  ident_before="$(frp_identity_status)"

  if [[ "$kind" != "source" && -z "$target_bundle" ]]; then
    frp_client_report_identity "$previous" "unknown" \
      "$installed_channel" "unknown" "$installed_ref" "unknown" \
      "$installed_bundle" "unknown"
    echo "FRP version               : ${FRP_VERSION}"
    echo
    frp_client_emit_legacy_secure_bridge
    return 1
  fi
  if [[ "$kind" != "source" ]] && ! frp_client_has_trustworthy_release_line \
      && [[ -z "$expected_channel" ]]; then
    frp_client_report_identity "$previous" "unknown" \
      "$installed_channel" "unknown" "$installed_ref" "unknown" \
      "$installed_bundle" "${target_bundle:-unknown}"
    echo "FRP version               : ${FRP_VERSION}"
    echo
    frp_client_emit_legacy_secure_bridge
    return 1
  fi

  if ! candidate_meta="$(frp_validate_release_source_metadata "$source" \
      "$expected_ref" "$expected_channel")"; then
    frp_emit_failure_class WRONG_METADATA
    return 1
  fi
  target="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $1}')"
  candidate_channel="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $2}')"
  candidate_ref="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $3}')"
  PROJECT_VERSION="$target"
  frp_client_upgrade_source_version "$source"
  PROJECT_VERSION="$target"

  # Mixed-version policy: server first. Block Client N against Server N-1.
  if [[ "${FRP_CLIENT_SKIP_SERVER_VERSION_GATE:-}" != "1" ]]; then
    frp_client_require_server_compatible_for_upgrade "$target" || return 1
  fi

  target_channel_out="$candidate_channel"
  target_ref_out="$candidate_ref"
  target_bundle_out="${target_bundle:-unknown}"
  frp_client_report_identity "$previous" "$target" \
    "$installed_channel" "$target_channel_out" \
    "$installed_ref" "$target_ref_out" \
    "$installed_bundle" "$target_bundle_out"
  echo "FRP version               : ${FRP_VERSION}"
  echo

  if [[ "$previous" != "legacy / unknown" ]]; then
    local vcmp
    vcmp="$(frp_version_compare "$previous" "$target")"
    if [[ "$vcmp" == "gt" ]]; then
      echo "ERROR: installed project version ${previous} is newer than this bundle (${target})." >&2
      echo "Refusing to downgrade." >&2
      frp_emit_failure_class DOWNGRADE_REFUSED
      return 1
    fi
    if [[ "$vcmp" == "eq" ]]; then
      if [[ -n "$target_bundle" && "$installed_bundle" == "$target_bundle" ]]; then
        update_needed=0
      else
        update_needed=1
      fi
    fi
  fi

  if [[ "$check_only" == "1" ]]; then
    if [[ "$update_needed" == "0" ]]; then
      echo "Update                    : not needed"
    else
      echo "Update                    : available"
    fi
    echo "State mutation           : NO"
    echo
    echo "A software update does not require an Enrollment Code."
    echo "Client state, public ports, and management identity are preserved."
    return 0
  fi

  if [[ "$update_needed" == "0" ]]; then
    echo "Update                    : not needed"
    return 0
  fi

  echo "Checking existing client state..."
  state_before="$(frp_client_digest "$(frp_client_state_path)")"
  toml_before="$(frp_client_digest "$(frp_client_toml_path)")"
  access_before="$(frp_client_digest "$(frp_client_access_path)")"
  key_before="$(frp_client_digest "$(frp_client_identity_key_path)")"
  pub_before="$(frp_client_digest "$(frp_client_identity_pub_path)")"
  mac_before="$(frp_client_digest "$(frp_client_identity_mac_path)")"

  staged="$(mktemp -d)"
  backup=""
  # shellcheck disable=SC2064
  trap 'rm -rf "'"$staged"'"; _frp_client_upgrade_release_lock' RETURN

  echo "Staging new management files..."
  frp_client_upgrade_stage "$source" "$staged" || return 1

  echo "Validating staged files..."
  if ! frp_client_upgrade_validate_staged "$staged"; then
    echo "ERROR: staged update failed validation; existing installation was not changed." >&2
    echo "UPGRADE_ROLLBACK=NOT_REQUIRED"
    return 1
  fi

  echo "Backing up replaceable project files..."
  backup="$(frp_client_upgrade_backup_tools)" || return 1
  FRP_TXN_SNAPSHOT_PATH="$backup" \
  FRP_TXN_RELEASE_CHANNEL="$candidate_channel" \
  FRP_TXN_SOURCE_REF="$candidate_ref" \
  FRP_TXN_BUNDLE_SHA256="${target_bundle:-}" \
  FRP_TXN_MUTATION_STARTED=true \
    frp_txn_write client-update commit "$previous" "$target"
  _FRP_CLIENT_UPGRADE_MUTATION_STARTED=1
  _FRP_CLIENT_UPGRADE_BACKUP="$backup"
  trap '_frp_client_upgrade_err; rm -rf "'"$staged"'"; return 1' ERR
  if [[ "$-" != *E* ]]; then
    set -E
    _FRP_CLIENT_UPGRADE_SET_E=1
  fi

  echo "Installing management files..."
  if ! frp_client_upgrade_install_staged "$staged"; then
    echo "ERROR: tool install failed; restoring previous management files." >&2
    frp_client_upgrade_rollback "$backup" FILE_COMMIT_FAILED || return 2
    return 1
  fi
  if ! frp_client_upgrade_post_mutation_guard; then
    echo "ERROR: unexpected post-mutation failure; restoring previous management files." >&2
    frp_client_upgrade_rollback "$backup" FILE_COMMIT_FAILED || return 2
    return 1
  fi

  echo "Verifying upgrade..."
  if ! frp_client_upgrade_verify "$ident_before"; then
    echo "ERROR: post-upgrade verification failed; restoring previous management files." >&2
    frp_client_upgrade_rollback "$backup" HEALTH_CHECK_FAILED || return 2
    return 1
  fi

  echo "Writing project version..."
  if [[ "${FRP_CLIENT_UPGRADE_HOOK_FAIL:-}" == "version" ]]; then
    echo "ERROR: simulated version/build-info write failure" >&2
    frp_client_upgrade_rollback "$backup" BUILD_INFO_WRITE_FAILED || return 2
    return 1
  fi
  if ! FRP_RELEASE_CHANNEL="$candidate_channel" \
      FRP_BUNDLE_SHA256="${target_bundle:-}" \
      FRP_VERSION_REQUIRE_VERIFIED_BUNDLE=1 \
      PROJECT_VERSION="$target" \
      frp_client_write_version_file; then
    echo "ERROR: failed to write version file; restoring previous management files." >&2
    frp_client_upgrade_rollback "$backup" BUILD_INFO_WRITE_FAILED || return 2
    return 1
  fi

  if [[ "$(frp_client_digest "$(frp_client_state_path)")" != "$state_before" ]]; then
    echo "ERROR: client-state.json changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi
  if [[ -n "$toml_before" && "$(frp_client_digest "$(frp_client_toml_path)")" != "$toml_before" ]]; then
    echo "ERROR: frpc.toml changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi
  if [[ -n "$access_before" && "$(frp_client_digest "$(frp_client_access_path)")" != "$access_before" ]]; then
    echo "ERROR: access-info.txt changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi
  if [[ -n "$key_before" && "$(frp_client_digest "$(frp_client_identity_key_path)")" != "$key_before" ]]; then
    echo "ERROR: management identity changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi
  if [[ -n "$pub_before" && "$(frp_client_digest "$(frp_client_identity_pub_path)")" != "$pub_before" ]]; then
    echo "ERROR: management public identity changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi
  if [[ -n "$mac_before" && "$(frp_client_digest "$(frp_client_identity_mac_path)")" != "$mac_before" ]]; then
    echo "ERROR: management identity MAC changed during software upgrade; restoring tools." >&2
    frp_client_upgrade_rollback "$backup" STATE_PRESERVATION_FAILED || return 2
    return 1
  fi

  ident_after="$(frp_identity_label)"
  frp_after="${FRP_VERSION}"
  _FRP_CLIENT_UPGRADE_MUTATION_STARTED=0
  trap - ERR
  if [[ "${_FRP_CLIENT_UPGRADE_SET_E:-0}" == "1" ]]; then
    set +E
  fi
  frp_txn_clear client
  frp_audit_emit client_update.completed
  echo
  echo "Upgrade complete."
  echo "Project version : ${previous} -> ${target}"
  echo "Release channel : ${candidate_channel}"
  echo "Source ref      : ${candidate_ref}"
  if [[ -n "$target_bundle" ]]; then
    echo "Bundle SHA256   : ${target_bundle}"
  fi
  if [[ "$previous" == "$target" ]]; then
    echo "Same-version update : refreshed management files"
  fi
  if [[ "$frp_before" == "$frp_after" ]]; then
    echo "FRP version     : ${frp_after} (unchanged)"
  else
    echo "FRP version     : ${frp_before} -> ${frp_after}"
  fi
  echo "Client state    : preserved"
  echo "Management ID   : ${ident_after}"
  echo "frpc restarted  : NO"
  echo "Enrollment Code : NOT REQUIRED"
  return 0
}

frp_verify_client_update_artifact() {
  local archive="$1"
  local sums_file="${2:-}"
  local expected=""
  expected="${FRP_CLIENT_UPDATE_SHA256:-}"
  if [[ -z "$expected" && -n "${FRP_RELEASE_SHA256SUMS_FILE:-}" ]]; then
    sums_file="${FRP_RELEASE_SHA256SUMS_FILE}"
  fi
  if [[ -z "$expected" && -n "$sums_file" && -f "$sums_file" ]]; then
    expected="$(awk '$2=="dist/bootstrap-client.sh" {print $1; exit}' "$sums_file")"
  fi
  if [[ -z "$expected" ]]; then
    echo "ERROR: update integrity metadata does not contain dist/bootstrap-client.sh" >&2
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  fi
  expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: malformed SHA256 in client update integrity metadata" >&2
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  fi
  if ! frp_verify_sha256 "$expected" "$archive" >/dev/null; then
    echo "ERROR: downloaded client update failed SHA256 verification" >&2
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  fi
  FRP_VERIFIED_CLIENT_UPDATE_SHA256="$expected"
  return 0
}

frp_client_fetch_and_upgrade() {
  local source="${1:-}"
  local check_only="${2:-0}"
  local tmp archive metadata channel source_ref explicit_channel=""
  if [[ -n "$source" ]]; then
    _FRP_CLIENT_UPDATE_KIND=source frp_client_apply_upgrade "$source" "$check_only"
    return $?
  fi
  if [[ "${FRP_CLIENT_UPGRADE_HOOK_DOWNLOAD_FAIL:-}" == "1" ]]; then
    echo "ERROR: failed to download the client update bundle" >&2
    return 1
  fi
  if [[ ${EUID} -ne 0 && -z "${FRP_CLIENT_TEST_ROOT:-}" ]]; then
    echo "ERROR: run with sudo" >&2
    return 1
  fi
  if ! frp_validate_https_url "$FRP_CLIENT_UPDATE_URL"; then
    echo "ERROR: client update URL must be a valid HTTPS URL" >&2
    return 1
  fi
  if ! frp_validate_https_url "$FRP_CLIENT_UPDATE_METADATA_URL"; then
    echo "ERROR: client update metadata URL must be a valid HTTPS URL" >&2
    return 1
  fi
  explicit_channel="$(frp_client_explicit_expected_channel || true)"
  if frp_client_has_existing_install; then
    if ! frp_client_has_trustworthy_release_line && [[ -z "$explicit_channel" ]]; then
      frp_client_report_identity \
        "$(frp_client_installed_project_version)" "unknown" \
        "$(frp_client_installed_release_channel)" "unknown" \
        "$(frp_client_installed_source_ref)" "unknown" \
        "$(frp_client_installed_bundle_sha256)" "unknown"
      frp_client_emit_legacy_secure_bridge
      return 1
    fi
  fi
  if [[ -n "$explicit_channel" ]]; then
    channel="$explicit_channel"
  elif frp_client_has_trustworthy_release_line; then
    channel="$(frp_client_known_release_channel "$(frp_client_installed_release_channel)")"
  else
    channel="$(frp_release_channel)"
  fi
  if [[ -n "${FRP_EXPECTED_SOURCE_REF:-}" ]]; then
    source_ref="$FRP_EXPECTED_SOURCE_REF"
  elif [[ "$channel" == "dev" ]]; then
    source_ref="main"
  else
    source_ref="v${PROJECT_VERSION}"
  fi
  if ! frp_url_has_source_ref "$FRP_CLIENT_UPDATE_URL" "$source_ref" \
    || ! frp_url_has_source_ref "$FRP_CLIENT_UPDATE_METADATA_URL" "$source_ref"; then
    echo "ERROR: client update artifact and metadata URLs must use source ref ${source_ref}" >&2
    return 1
  fi
  tmp="$(mktemp -d)"
  archive="${tmp}/bootstrap-client.sh"
  metadata="${tmp}/SHA256SUMS"
  trap 'rm -rf "'"$tmp"'"' RETURN
  echo "Downloading frp-auto-deploy client update bundle..."
  curl -fL --retry 3 --connect-timeout 10 --max-time 120 -o "$metadata" "$FRP_CLIENT_UPDATE_METADATA_URL" || {
    echo "ERROR: failed to download client update integrity metadata" >&2
    frp_emit_failure_class INTEGRITY_FAILED
    return 1
  }
  curl -fL --retry 3 --connect-timeout 10 --max-time 120 -o "$archive" "$FRP_CLIENT_UPDATE_URL" || {
    echo "ERROR: failed to download the client update bundle" >&2
    frp_emit_failure_class DOWNLOAD_FAILED
    return 1
  }
  if ! frp_verify_client_update_artifact "$archive" "$metadata"; then
    return 1
  fi
  chmod 0755 "$archive"
  echo "Applying update from downloaded bundle..."
  # The bundle extracts a source tree and runs install-client.sh --upgrade.
  # FRP_BUNDLE_SHA256 is the externally verified digest from SHA256SUMS.
  if [[ "$check_only" == "1" ]]; then
    FRP_BUNDLE_SHA256="$FRP_VERIFIED_CLIENT_UPDATE_SHA256" \
      FRP_BUNDLE_FILE="$archive" FRP_RELEASE_CHANNEL="$channel" \
      FRP_EXPECTED_RELEASE_CHANNEL="$channel" \
      FRP_EXPECTED_SOURCE_REF="$source_ref" \
      _FRP_CLIENT_UPDATE_KIND=bundle \
      bash "$archive" --upgrade --check
  else
    FRP_BUNDLE_SHA256="$FRP_VERIFIED_CLIENT_UPDATE_SHA256" \
      FRP_BUNDLE_FILE="$archive" FRP_RELEASE_CHANNEL="$channel" \
      FRP_EXPECTED_RELEASE_CHANNEL="$channel" \
      FRP_EXPECTED_SOURCE_REF="$source_ref" \
      _FRP_CLIENT_UPDATE_KIND=bundle \
      bash "$archive" --upgrade
  fi
}
