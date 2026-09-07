#!/usr/bin/env bash
# Shared constants and helpers for FRP binary lifecycle management.
# Source this file; do not execute it.

if [[ -n "${FRP_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
FRP_COMMON_LOADED=1

# Defaults match VERSION. A sibling VERSION file overrides project/FRP versions.
PROJECT_VERSION="${PROJECT_VERSION:-2.2.0}"
FRP_VERSION="${FRP_VERSION:-0.71.0}"
# FRP 0.71.0 pkg/util/net/websocket.go FrpWebsocketPath. Not configurable.
FRP_WEBSOCKET_PATH="${FRP_WEBSOCKET_PATH:-/~!frp}"
FRP_SINGLE443_BACKEND_PORT="${FRP_SINGLE443_BACKEND_PORT:-7000}"
FRP_SHA256_AMD64="${FRP_SHA256_AMD64:-84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716}"
FRP_SHA256_ARM64="${FRP_SHA256_ARM64:-f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266}"
FRP_SHA256_DARWIN_ARM64="${FRP_SHA256_DARWIN_ARM64:-45be02b186860d375ed49a8941ae9569628a54bf14e67fc36b29c98c99dabcc6}"
FRP_SHA256_WINDOWS_AMD64="${FRP_SHA256_WINDOWS_AMD64:-9e5062e3e5cf07e67144a3a4acf175ef6a2486f3605dd6cf288bae34ab39819f}"

_FRP_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_FRP_COMMON_DIR}/../VERSION" ]]; then
  # shellcheck disable=SC1091
  . "${_FRP_COMMON_DIR}/../VERSION"
fi

FRP_GITHUB_OWNER="${FRP_GITHUB_OWNER:-datarelay-labs}"
FRP_GITHUB_REPO="${FRP_GITHUB_REPO:-frp-auto-deploy}"
FRP_GITHUB_RAW_HOST="${FRP_GITHUB_RAW_HOST:-raw.githubusercontent.com}"

frp_os() {
  local raw="${FRP_TEST_UNAME_S:-}"
  if [[ -z "$raw" ]]; then
    if [[ -z "${_FRP_UNAME_S_CACHE:-}" ]]; then
      _FRP_UNAME_S_CACHE="$(uname -s 2>/dev/null || printf 'Linux')"
    fi
    raw="$_FRP_UNAME_S_CACHE"
  fi
  case "$raw" in
    Darwin|darwin) printf 'darwin' ;;
    *) printf 'linux' ;;
  esac
}

frp_is_darwin() {
  [[ "$(frp_os)" == darwin ]]
}

frp_detect_os() {
  local raw="${FRP_TEST_UNAME_S:-$(uname -s 2>/dev/null || printf 'Linux')}"
  case "$raw" in
    Linux|linux) FRP_OS=linux ;;
    Darwin|darwin) FRP_OS=darwin ;;
    *)
      echo "ERROR: unsupported operating system: ${raw}" >&2
      echo "This release supports Linux and Apple Silicon macOS." >&2
      return 1
      ;;
  esac
  printf '%s' "$FRP_OS"
}

frp_normalize_release_channel() {
  local ch
  ch="$(printf '%s' "${1:-stable}" | tr '[:upper:]' '[:lower:]')"
  case "$ch" in
    dev|main|development) printf 'dev' ;;
    *) printf 'stable' ;;
  esac
}

frp_version_state_file() {
  local root="${FRP_DEPLOY_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-${FRP_CTL_TEST_ROOT:-${FRP_UPDATE_ROOT:-${FRP_SERVER_TEST_ROOT:-}}}}}"
  local p
  p="$(frp_platform_map_path /etc/frp-auto-deploy/version)"
  if [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_parse_known_release_channel() {
  local ch
  ch="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$ch" in
    dev|main|development) printf 'dev' ;;
    stable) printf 'stable' ;;
    *) return 1 ;;
  esac
}

frp_txn_field() {
  local field="$1" marker role="${FRP_TXN_ROLE:-}"
  if [[ -z "$role" ]]; then
    return 0
  fi
  frp_txn_adopt_legacy_marker "$role" 2>/dev/null || true
  marker="$(frp_txn_marker_path "$role")" || return 0
  [[ -f "$marker" ]] || return 0
  python3 - "$marker" "$field" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
value = data.get(sys.argv[2])
if value is None or value == "":
    raise SystemExit(0)
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

frp_resolve_project_update_identity() {
  # Sets FRP_RESOLVED_RELEASE_CHANNEL and FRP_RESOLVED_SOURCE_REF.
  # Never silently defaults an unknown install to stable.
  local txn_ch txn_ref persisted persisted_ref
  local server_marker
  FRP_RESOLVED_RELEASE_CHANNEL=""
  FRP_RESOLVED_SOURCE_REF=""
  if [[ -n "${FRP_RELEASE_CHANNEL:-}" ]]; then
    if ! FRP_RESOLVED_RELEASE_CHANNEL="$(frp_parse_known_release_channel "$FRP_RELEASE_CHANNEL")"; then
      echo "ERROR: FRP_RELEASE_CHANNEL must be dev or stable" >&2
      return 1
    fi
    if [[ "$FRP_RESOLVED_RELEASE_CHANNEL" == "dev" ]]; then
      FRP_RESOLVED_SOURCE_REF="main"
    else
      FRP_RESOLVED_SOURCE_REF="v${PROJECT_VERSION}"
    fi
    return 0
  fi
  # Project-update identity recovery reads the server transaction marker only.
  FRP_TXN_ROLE=server
  export FRP_TXN_ROLE
  txn_ch="$(frp_txn_field release_channel)"
  txn_ref="$(frp_txn_field source_ref)"
  if [[ -n "$txn_ch" || -n "$txn_ref" ]]; then
    if [[ -z "$txn_ch" || -z "$txn_ref" ]] || \
       ! FRP_RESOLVED_RELEASE_CHANNEL="$(frp_parse_known_release_channel "$txn_ch")"; then
      echo "ERROR: pending transaction does not identify a safe release line." >&2
      echo "Set FRP_RELEASE_CHANNEL=dev or FRP_RELEASE_CHANNEL=stable explicitly." >&2
      return 1
    fi
    FRP_RESOLVED_SOURCE_REF="$txn_ref"
    return 0
  fi
  persisted="$(frp_read_kv_file "$(frp_version_state_file)" RELEASE_CHANNEL)"
  persisted_ref="$(frp_read_kv_file "$(frp_version_state_file)" SOURCE_REF)"
  if [[ -n "$persisted" ]] && FRP_RESOLVED_RELEASE_CHANNEL="$(frp_parse_known_release_channel "$persisted")"; then
    if [[ -n "$persisted_ref" ]]; then
      FRP_RESOLVED_SOURCE_REF="$persisted_ref"
    elif [[ "$FRP_RESOLVED_RELEASE_CHANNEL" == "dev" ]]; then
      FRP_RESOLVED_SOURCE_REF="main"
    else
      FRP_RESOLVED_SOURCE_REF="v${PROJECT_VERSION}"
    fi
    return 0
  fi
  server_marker="$(frp_txn_marker_path server)"
  if [[ -f "$server_marker" ]] || [[ -f "$(frp_txn_legacy_marker_path)" ]]; then
    echo "ERROR: pending transaction does not identify a safe release line." >&2
    echo "Set FRP_RELEASE_CHANNEL=dev or FRP_RELEASE_CHANNEL=stable explicitly." >&2
    return 1
  fi
  echo "ERROR: installed release channel is unknown; refusing to guess stable." >&2
  echo "Set FRP_RELEASE_CHANNEL=dev or FRP_RELEASE_CHANNEL=stable explicitly." >&2
  return 1
}

frp_persisted_release_channel() {
  local file ch
  file="$(frp_version_state_file)"
  ch="$(frp_read_kv_file "$file" RELEASE_CHANNEL)"
  if [[ -z "$ch" ]]; then
    return 0
  fi
  frp_normalize_release_channel "$ch"
}

frp_release_channel() {
  local ch
  if [[ -n "${FRP_RELEASE_CHANNEL:-}" ]]; then
    frp_normalize_release_channel "$FRP_RELEASE_CHANNEL"
    return 0
  fi
  ch="$(frp_persisted_release_channel)"
  if [[ -n "$ch" ]]; then
    printf '%s' "$ch"
    return 0
  fi
  printf 'stable'
}

frp_release_git_ref() {
  if [[ "$(frp_release_channel)" == "dev" ]]; then
    printf 'main'
  else
    printf 'v%s' "${PROJECT_VERSION}"
  fi
}

frp_github_raw_url() {
  local rel="${1:-}"
  rel="${rel#/}"
  printf 'https://%s/%s/%s/%s/%s' \
    "$FRP_GITHUB_RAW_HOST" "$FRP_GITHUB_OWNER" "$FRP_GITHUB_REPO" \
    "$(frp_release_git_ref)" "$rel"
}

frp_default_client_installer_url() {
  frp_github_raw_url dist/bootstrap-client.sh
}

frp_default_windows_client_installer_url() {
  frp_github_raw_url dist/bootstrap-client.ps1
}

frp_default_client_update_url() {
  frp_github_raw_url dist/bootstrap-client.sh
}

frp_default_client_update_metadata_url() {
  frp_github_raw_url SHA256SUMS
}

frp_default_server_project_update_url() {
  frp_github_raw_url dist/bootstrap-server.sh
}

frp_default_release_sha256sums_url() {
  frp_github_raw_url SHA256SUMS
}

frp_sha256sum_entry() {
  local sums_file="$1" artifact="$2"
  [[ -f "$sums_file" ]] || return 1
  awk -v name="$artifact" '
    $2 == name && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ {
      if (found) exit 2
      digest=tolower($1)
      found=1
    }
    END {
      if (found == 1) print digest
      else exit 1
    }
  ' "$sums_file"
}

frp_validate_https_url() {
  local url="${1:-}"
  python3 - "$url" <<'PY'
import sys
from urllib.parse import urlsplit

url = sys.argv[1]
if url.strip() != url or any(ord(ch) < 32 or ord(ch) == 127 for ch in url) or any(ch.isspace() for ch in url):
    raise SystemExit(1)
try:
    parsed = urlsplit(url)
    port = parsed.port
except (TypeError, ValueError):
    raise SystemExit(1)
if (
    parsed.scheme != "https"
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or port is not None and not (1 <= port <= 65535)
):
    raise SystemExit(1)
PY
}

frp_url_has_source_ref() {
  local url="${1:-}" ref="${2:-}"
  python3 - "$url" "$ref" <<'PY'
import sys
from urllib.parse import unquote, urlsplit

parts = [unquote(part) for part in urlsplit(sys.argv[1]).path.split("/") if part]
raise SystemExit(0 if sys.argv[2] in parts else 1)
PY
}

frp_is_official_main_installer_url() {
  local url="${1:-}"
  [[ "$url" == "https://${FRP_GITHUB_RAW_HOST}/${FRP_GITHUB_OWNER}/${FRP_GITHUB_REPO}/main/dist/bootstrap-client.sh" ]]
}

frp_validate_release_source_metadata() {
  # Validate VERSION + release-manifest.json agreement.
  # Prints: project_version<TAB>channel<TAB>git_ref
  local source="$1"
  local expected_ref="${2:-${FRP_EXPECTED_SOURCE_REF:-}}"
  local expected_channel="${3:-${FRP_EXPECTED_RELEASE_CHANNEL:-}}"
  python3 - "${source}/release-manifest.json" "${source}/VERSION" \
    "$expected_ref" "$expected_channel" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest_path, version_path, expected_ref, expected_channel = sys.argv[1:]
try:
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
except Exception:
    sys.stderr.write("ERROR: missing or invalid release-manifest.json\n")
    raise SystemExit(1)
values = {}
try:
    for line in Path(version_path).read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
except OSError:
    sys.stderr.write("ERROR: missing VERSION metadata\n")
    raise SystemExit(1)
project = values.get("PROJECT_VERSION", "")
if not re.fullmatch(r"\d+\.\d+\.\d+", project):
    sys.stderr.write("ERROR: invalid project version metadata\n")
    raise SystemExit(1)
if str(data.get("project_version") or "") != project:
    sys.stderr.write("ERROR: release metadata project version mismatch\n")
    raise SystemExit(1)
channel = str(data.get("channel") or "").strip().lower()
git_ref = str(data.get("git_ref") or "").strip()
if channel not in ("dev", "stable"):
    sys.stderr.write("ERROR: release metadata channel must be dev or stable\n")
    raise SystemExit(1)
expected_git_ref = "main" if channel == "dev" else "v%s" % project
if git_ref != expected_git_ref:
    sys.stderr.write("ERROR: release metadata channel/ref disagreement\n")
    raise SystemExit(1)
if expected_ref and git_ref != expected_ref:
    sys.stderr.write("ERROR: release metadata source ref mismatch\n")
    raise SystemExit(1)
if expected_channel and channel != expected_channel:
    sys.stderr.write("ERROR: release metadata channel mismatch\n")
    raise SystemExit(1)
sys.stdout.write("%s\t%s\t%s\n" % (project, channel, git_ref))
PY
}

frp_release_manifest_path() {
  if [[ -n "${FRP_RELEASE_MANIFEST:-}" && -f "${FRP_RELEASE_MANIFEST}" ]]; then
    printf '%s' "$FRP_RELEASE_MANIFEST"
    return 0
  fi
  if [[ -f "${_FRP_COMMON_DIR}/../release-manifest.json" ]]; then
    printf '%s' "${_FRP_COMMON_DIR}/../release-manifest.json"
    return 0
  fi
  if [[ -f /usr/local/lib/frp-auto-deploy/release-manifest.json ]]; then
    printf '%s' /usr/local/lib/frp-auto-deploy/release-manifest.json
    return 0
  fi
  return 1
}

frp_release_artifact_sha256() {
  local name="${1:-bootstrap-client.sh}" path
  path="$(frp_release_manifest_path)" || return 1
  python3 - "$path" "$name" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
try:
    data = json.loads(open(path, encoding='utf-8').read())
except Exception:
    raise SystemExit(1)
art = (data.get('artifacts') or {}).get(name) or {}
digest = str(art.get('sha256') or '').strip().lower()
if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
    raise SystemExit(1)
print(digest)
PY
}

FRP_TEST_HARNESS_MAGIC="frp-auto-deploy-test-harness"

frp_test_harness_enabled() {
  [[ "${FRP_UPDATE_TEST_HARNESS:-}" == "1" ]] || return 1
  local marker="${FRP_UPDATE_TEST_MARKER:-}"
  [[ -n "$marker" && -f "$marker" ]] || return 1
  [[ "$(tr -d '\n' <"$marker")" == "$FRP_TEST_HARNESS_MAGIC" ]] || return 1
  return 0
}

frp_path() {
  local p
  p="$(frp_platform_map_path "$1")"
  local root="${FRP_DEPLOY_TEST_ROOT:-${FRP_UPDATE_ROOT:-}}"
  if frp_test_harness_enabled && [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_platform_map_path() {
  local p="${1:-}"
  if frp_is_darwin && declare -F frp_macos_map_path >/dev/null 2>&1; then
    frp_macos_map_path "$p"
  else
    printf '%s' "$p"
  fi
}

frp_detect_arch() {
  local machine os
  machine="${FRP_TEST_UNAME_M:-$(uname -m)}"
  os="$(frp_os)"
  FRP_OS="$os"
  if [[ "$os" == darwin ]]; then
    case "$machine" in
      arm64|aarch64)
        FRP_ARCH=arm64
        EXPECTED_SHA="$FRP_SHA256_DARWIN_ARM64"
        ;;
      *)
        echo "ERROR: unsupported macOS architecture: ${machine}" >&2
        echo "The macOS client requires Apple Silicon (arm64); Intel Macs are not supported." >&2
        if [[ "${FRP_TEST_PROC_TRANSLATED:-}" == "1" ]] || \
           { command -v sysctl >/dev/null 2>&1 && [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" == "1" ]]; }; then
          echo "This shell is running under Rosetta 2; re-run with: arch -arm64 /bin/bash" >&2
        fi
        return 1
        ;;
    esac
    return 0
  fi
  case "$machine" in
    x86_64)
      FRP_ARCH=amd64
      EXPECTED_SHA="${FRP_SHA256_AMD64}"
      ;;
    aarch64|arm64)
      FRP_ARCH=arm64
      EXPECTED_SHA="${FRP_SHA256_ARM64}"
      ;;
    *)
      echo "ERROR: unsupported architecture: ${machine}" >&2
      return 1
      ;;
  esac
}

frp_detect_architecture() {
  frp_detect_arch
}

frp_checksum_for() {
  local version="$1" arch="$2" os="${3:-$(frp_os)}"
  if [[ "$version" != "$FRP_VERSION" ]]; then
    echo "ERROR: FRP ${version} is not the tested version (${FRP_VERSION})" >&2
    return 1
  fi
  case "${os}/${arch}" in
    linux/amd64) printf '%s' "$FRP_SHA256_AMD64" ;;
    linux/arm64) printf '%s' "$FRP_SHA256_ARM64" ;;
    darwin/arm64) printf '%s' "$FRP_SHA256_DARWIN_ARM64" ;;
    darwin/*)
      echo "ERROR: macOS is supported on Apple Silicon (arm64) only; got ${arch}" >&2
      return 1
      ;;
    *)
      echo "ERROR: unsupported architecture: ${arch}" >&2
      return 1
      ;;
  esac
}

frp_release_url() {
  local version="$1" arch="$2" os="${3:-$(frp_os)}"
  case "$os" in
    linux|darwin) ;;
    *) echo "ERROR: unsupported operating system: ${os}" >&2; return 1 ;;
  esac
  printf 'https://github.com/fatedier/frp/releases/download/v%s/frp_%s_%s_%s.tar.gz' \
    "$version" "$version" "$os" "$arch"
}

frp_parse_binary_version() {
  local bin="$1" out
  if [[ ! -x "$bin" ]]; then
    printf '%s' "unknown"
    return 0
  fi
  out="$("$bin" --version 2>/dev/null | head -n 1 || true)"
  printf '%s' "$out" | python3 -c '
import re,sys
text=sys.stdin.read()
m=re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", text)
sys.stdout.write(m.group(1) if m else "unknown")
'
}

frp_file_sha256() {
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

frp_verify_sha256() {
  local expected="$1" file="$2"
  python3 - "$expected" "$file" <<'PY'
import hashlib, sys
from pathlib import Path
expected, path = sys.argv[1], sys.argv[2]
actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
if actual.lower() != expected.lower():
    sys.stderr.write("ERROR: SHA256 checksum mismatch\n")
    sys.exit(1)
print(path + ": OK")
PY
}

frp_atomic_install() {
  local src="$1" dest="$2" mode="${3:-0755}"
  local dir tmp
  frp_require_safe_write_path "$dest" || return 1
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.frp-install.XXXXXX")"
  cp "$src" "$tmp"
  chmod "$mode" "$tmp"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
}

frp_write_version_file() {
  local dest="$1"
  local dir tmp channel source_ref bundle existing
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  if [[ -n "${FRP_RELEASE_CHANNEL:-}" ]]; then
    channel="$(frp_normalize_release_channel "$FRP_RELEASE_CHANNEL")"
  else
    existing="$(frp_read_kv_file "$dest" RELEASE_CHANNEL)"
    if [[ -n "$existing" ]]; then
      channel="$(frp_normalize_release_channel "$existing")"
    else
      channel="$(frp_release_channel)"
    fi
  fi
  if [[ "$channel" == "dev" ]]; then
    source_ref="main"
  else
    source_ref="v${PROJECT_VERSION}"
  fi
  bundle="${FRP_BUNDLE_SHA256:-}"
  if [[ "${FRP_VERSION_REQUIRE_VERIFIED_BUNDLE:-}" == "1" ]]; then
    if [[ ! "$bundle" =~ ^[0-9a-fA-F]{64}$ ]]; then
      bundle=""
    fi
  else
    if [[ -z "$bundle" && -n "${FRP_BUNDLE_FILE:-}" && -f "${FRP_BUNDLE_FILE}" ]]; then
      bundle="$(sha256sum "${FRP_BUNDLE_FILE}" | awk '{print $1}')"
    fi
    if [[ -z "$bundle" ]]; then
      bundle="$(frp_read_kv_file "$dest" BUNDLE_SHA256)"
    fi
    if [[ -z "$bundle" ]]; then
      local cand=""
      if [[ "${2:-}" == "client" ]]; then
        cand="${_FRP_COMMON_DIR}/../dist/bootstrap-client.sh"
      else
        cand="${_FRP_COMMON_DIR}/../dist/bootstrap-server.sh"
      fi
      if [[ -f "$cand" ]]; then
        bundle="$(sha256sum "$cand" | awk '{print $1}')"
      fi
    fi
  fi
  tmp="$(mktemp "${dir}/.version.XXXXXX")"
  {
    printf 'PROJECT_VERSION=%s\n' "${PROJECT_VERSION}"
    printf 'FRP_VERSION=%s\n' "${FRP_VERSION}"
    printf 'RELEASE_CHANNEL=%s\n' "${channel}"
    printf 'SOURCE_REF=%s\n' "${source_ref}"
    if [[ -n "$bundle" ]]; then
      printf 'BUNDLE_SHA256=%s\n' "$bundle"
    fi
  } >"$tmp"
  chmod 0644 "$tmp"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
}

frp_read_kv_file() {
  local file="$1" key="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  awk -F= -v k="$key" '$1==k {print substr($0, index($0,"=")+1); exit}' "$file"
}

frp_bind_port() {
  local config="$1"
  if [[ ! -f "$config" ]]; then
    return 0
  fi
  python3 - "$config" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
m = re.search(r"^\s*bindPort\s*=\s*(\d+)", text, re.M)
sys.stdout.write(m.group(1) if m else "")
PY
}

frp_port_listening() {
  local port="$1"
  local raw=""
  if ! frp_command_exists ss; then
    return 2
  fi
  if raw="$(frp_invoke ss -H -lnt 2>/dev/null)"; then
    :
  elif raw="$(frp_invoke ss -lnt 2>/dev/null)"; then
    :
  else
    return 2
  fi
  if printf '%s\n' "$raw" | awk -v wanted="$port" '
    $1 ~ /^(State|Netid)$/ { next }
    {
      p=$4
      gsub(/\]$/, "", p)
      sub(/^.*:/, "", p)
      if (p == wanted) found=1
    }
    END { exit(found ? 0 : 1) }
  '; then
    return 0
  fi
  return 1
}

frp_registry_identity() {
  local registry="$1"
  python3 - "$registry" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print("{}")
    raise SystemExit(0)
state = json.loads(p.read_text(encoding="utf-8"))
clients = {}
for mid, client in sorted((state.get("clients") or {}).items()):
    services = {}
    raw = client.get("services") or {}
    if isinstance(raw, dict):
        for sid, svc in sorted(raw.items()):
            if not isinstance(svc, dict):
                continue
            services[sid] = {
                "enabled": svc.get("enabled", True),
                "local_ip": svc.get("local_ip"),
                "local_port": svc.get("local_port"),
                "preset": svc.get("preset"),
                "remote_port": svc.get("remote_port"),
            }
    clients[mid] = {
        "hostname": client.get("hostname"),
        "services": services,
    }
print(json.dumps({
    "clients": clients,
    "reserved": sorted(state.get("reserved") or []),
    "schema_version": state.get("schema_version"),
}, sort_keys=True))
PY
}

frp_registry_readiness() {
  local registry="$1"
  python3 - "$registry" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print("none")
    print("missing")
    raise SystemExit(0)
try:
    state = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    print("unknown")
    print("invalid")
    raise SystemExit(0)
if not isinstance(state, dict):
    print("unknown")
    print("invalid")
    raise SystemExit(0)
version = state.get("schema_version")
if version is None:
    print("1")
    print("incompatible")
    raise SystemExit(0)
print(str(version))
if version != 2:
    print("incompatible")
    raise SystemExit(0)
clients = state.get("clients", {}) or {}
if not isinstance(clients, dict):
    print("incompatible")
    raise SystemExit(0)
for client in clients.values():
    if not isinstance(client, dict) or "ssh_port" in client or "https_port" in client:
        print("incompatible")
        raise SystemExit(0)
print("ready")
PY
}

frp_registry_counts() {
  local registry="$1"
  python3 - "$registry" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    print("0 0")
    raise SystemExit(0)
state = json.loads(p.read_text(encoding="utf-8"))
clients = state.get("clients") or {}
used = set()
for item in state.get("reserved") or []:
    try:
        used.add(int(item))
    except Exception:
        pass
for client in clients.values():
    if not isinstance(client, dict):
        continue
    services = client.get("services") or {}
    if not isinstance(services, dict):
        continue
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        value = svc.get("remote_port")
        if value:
            try:
                used.add(int(value))
            except Exception:
                pass
print(f"{len(clients)} {len(used)}")
PY
}

frp_valid_version() {
  local v="$1"
  printf '%s' "$v" | python3 -c '
import re,sys
sys.exit(0 if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sys.stdin.read().strip()) else 1)
'
}

frp_upstream_latest() {
  if [[ "${FRP_STATUS_SKIP_UPSTREAM:-}" == "1" ]]; then
    printf '%s' "unavailable"
    return 0
  fi
  python3 - <<'PY'
import json, sys, urllib.request
url = "https://api.github.com/repos/fatedier/frp/releases/latest"
req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "frp-auto-deploy"})
try:
    with urllib.request.urlopen(req, timeout=3) as resp:
        data = json.loads(resp.read().decode())
    tag = str(data.get("tag_name") or "").strip()
    if tag.startswith("v"):
        tag = tag[1:]
    sys.stdout.write(tag if tag else "unavailable")
except Exception:
    sys.stdout.write("unavailable")
PY
}

frp_has_disk_kb() {
  local path="$1" need_kb="$2" avail check="$1"
  while [[ ! -d "$check" && "$check" != "/" && -n "$check" ]]; do
    check="$(dirname "$check")"
  done
  avail="$(df -Pk "$check" 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ -z "$avail" ]]; then
    return 0
  fi
  [[ "$avail" -ge "$need_kb" ]]
}

# ---------------------------------------------------------------------------
# Cross-distro host detection (capability-based; not distro-id switches)
# ---------------------------------------------------------------------------

FRP_PYTHON_MIN_MAJOR=3
FRP_PYTHON_MIN_MINOR=7
FRP_BASH_MIN_MAJOR=4
FRP_BASH_MIN_MINOR=2
# systemd 232 introduced ProtectSystem=strict and ReadWritePaths.
FRP_SYSTEMD_HARDENING_MIN=232

frp_os_release_file() {
  printf '%s' "${FRP_OS_RELEASE_FILE:-/etc/os-release}"
}

frp_os_release_value() {
  local key="$1" file="$2" line value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "${key}="*)
        value="${line#*=}"
        if [[ "$value" == \"*\" ]]; then
          value="${value#\"}"
          value="${value%\"}"
        elif [[ "$value" == \'*\' ]]; then
          value="${value#\'}"
          value="${value%\'}"
        fi
        printf '%s' "$value"
        return 0
        ;;
    esac
  done <"$file"
}

frp_detect_platform() {
  local file pretty name
  DISTRO_ID="unknown"
  DISTRO_NAME="Linux"
  DISTRO_VERSION=""
  file="$(frp_os_release_file)"
  if [[ -r "$file" ]]; then
    DISTRO_ID="$(frp_os_release_value ID "$file")"
    DISTRO_ID="${DISTRO_ID:-unknown}"
    pretty="$(frp_os_release_value PRETTY_NAME "$file")"
    name="$(frp_os_release_value NAME "$file")"
    DISTRO_NAME="${pretty:-${name:-Linux}}"
    DISTRO_VERSION="$(frp_os_release_value VERSION_ID "$file")"
  fi
}

frp_command_exists() {
  local cmd="$1"
  if [[ -n "${FRP_TEST_CMD_PATH:-}" ]]; then
    PATH="${FRP_TEST_CMD_PATH}" command -v "$cmd" >/dev/null 2>&1
  else
    command -v "$cmd" >/dev/null 2>&1
  fi
}

frp_invoke() {
  local cmd="$1"
  shift
  if [[ -n "${FRP_TEST_CMD_PATH:-}" ]]; then
    PATH="${FRP_TEST_CMD_PATH}${PATH:+:$PATH}" command "$cmd" "$@"
  else
    command "$cmd" "$@"
  fi
}

frp_package_manager_exists() {
  local cmd="$1"
  if [[ -n "${FRP_TEST_PM_PATH:-}" ]]; then
    PATH="${FRP_TEST_PM_PATH}" command -v "$cmd" >/dev/null 2>&1
  else
    command -v "$cmd" >/dev/null 2>&1
  fi
}

frp_package_manager_bin() {
  local cmd="$1"
  if [[ -n "${FRP_TEST_PM_PATH:-}" ]]; then
    PATH="${FRP_TEST_PM_PATH}" command -v "$cmd"
  else
    command -v "$cmd"
  fi
}

frp_detect_package_manager() {
  PACKAGE_MANAGER=""
  if frp_package_manager_exists dnf; then
    PACKAGE_MANAGER=dnf
  elif frp_package_manager_exists yum; then
    PACKAGE_MANAGER=yum
  elif frp_package_manager_exists apt-get; then
    PACKAGE_MANAGER=apt
  fi
}

frp_systemd_runtime_dir() {
  printf '%s' "${FRP_TEST_SYSTEMD_RUNTIME_DIR:-/run/systemd/system}"
}

frp_systemd_usable() {
  [[ -d "$(frp_systemd_runtime_dir)" ]]
}

frp_require_systemd() {
  if ! frp_command_exists systemctl; then
    echo "ERROR: this release requires a systemd-based Linux distribution." >&2
    return 1
  fi
  if ! frp_systemd_usable; then
    echo "ERROR: this release requires a systemd-based Linux distribution." >&2
    return 1
  fi
}

frp_service_manager() {
  if frp_is_darwin; then
    if declare -F frp_launchd_usable >/dev/null 2>&1 && frp_launchd_usable; then
      printf 'launchd'
    else
      printf 'none'
    fi
  elif frp_command_exists systemctl && frp_systemd_usable; then
    printf 'systemd'
  else
    printf 'none'
  fi
}

frp_require_service_manager() {
  if frp_is_darwin; then
    if ! declare -F frp_launchd_usable >/dev/null 2>&1 || ! frp_launchd_usable; then
      echo "ERROR: this release requires launchd (launchctl) on macOS." >&2
      return 1
    fi
    return 0
  fi
  frp_require_systemd
}

frp_systemd_version() {
  local v="${FRP_TEST_SYSTEMD_VERSION:-}"
  if [[ -n "$v" ]]; then
    printf '%s' "$v"
    return 0
  fi
  if ! frp_command_exists systemctl; then
    return 0
  fi
  frp_invoke systemctl --version 2>/dev/null | awk 'NR==1 {print $2; exit}'
}

frp_systemd_supports_service_hardening() {
  local v
  v="$(frp_systemd_version)"
  if [[ ! "$v" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  [[ "$v" -ge "$FRP_SYSTEMD_HARDENING_MIN" ]]
}

# Strip directives that systemd 219 (Amazon Linux 2) cannot honor.
# Unknown ProtectSystem=strict values can fail unit load on old systemd.
frp_write_compatible_systemd_unit() {
  local src="$1" dest="$2"
  local tmp
  if frp_systemd_supports_service_hardening; then
    install -m 0644 "$src" "$dest"
    return 0
  fi
  tmp="$(mktemp)"
  grep -vE '^(NoNewPrivileges|ProtectSystem|ReadWritePaths)=' "$src" >"$tmp"
  install -m 0644 "$tmp" "$dest"
  rm -f "$tmp"
}

frp_print_detected_linux() {
  local pm="${PACKAGE_MANAGER:-none}"
  local init="unknown"
  if frp_command_exists systemctl && frp_systemd_usable; then
    init="systemd"
  fi
  echo "Detected Linux:"
  echo "  Distribution : ${DISTRO_NAME}"
  echo "  Package mgr  : ${pm}"
  echo "  Architecture : ${FRP_ARCH:-unknown}"
  echo "  Init system  : ${init}"
}

frp_require_bash() {
  if (( BASH_VERSINFO[0] < FRP_BASH_MIN_MAJOR || \
        (BASH_VERSINFO[0] == FRP_BASH_MIN_MAJOR && BASH_VERSINFO[1] < FRP_BASH_MIN_MINOR) )); then
    echo "ERROR: Bash ${FRP_BASH_MIN_MAJOR}.${FRP_BASH_MIN_MINOR} or newer is required (found ${BASH_VERSION})." >&2
    return 1
  fi
}

frp_require_python() {
  if ! frp_command_exists python3; then
    echo "ERROR: python3 ${FRP_PYTHON_MIN_MAJOR}.${FRP_PYTHON_MIN_MINOR} or newer is required." >&2
    return 1
  fi
  if ! frp_invoke python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (${FRP_PYTHON_MIN_MAJOR}, ${FRP_PYTHON_MIN_MINOR}) else 1)"; then
    echo "ERROR: python3 ${FRP_PYTHON_MIN_MAJOR}.${FRP_PYTHON_MIN_MINOR} or newer is required." >&2
    echo "This host's python3 is too old for frp-auto-deploy." >&2
    return 1
  fi
}

frp_python_version_ok() {
  frp_command_exists python3 || return 1
  frp_invoke python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (${FRP_PYTHON_MIN_MAJOR}, ${FRP_PYTHON_MIN_MINOR}) else 1)"
}

frp_el8_family() {
  local id ver
  id="$(printf '%s' "${DISTRO_ID:-}" | tr '[:upper:]' '[:lower:]')"
  ver="$(printf '%s' "${DISTRO_VERSION:-}" | cut -d. -f1)"
  case "$id" in
    rhel|centos|rocky|almalinux|ol)
      [[ "$ver" == "8" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

frp_prefer_newer_python() {
  # On EL8 the `python3` package is often 3.6. Prefer an installed 3.9+ binary
  # via an early PATH shim without rewriting the distro /usr/bin/python3.
  local candidate shimdir
  if frp_python_version_ok; then
    return 0
  fi
  for candidate in python3.12 python3.11 python3.10 python3.9 python3.8; do
    if frp_command_exists "$candidate" && \
       frp_invoke "$candidate" -c "import sys; raise SystemExit(0 if sys.version_info >= (${FRP_PYTHON_MIN_MAJOR}, ${FRP_PYTHON_MIN_MINOR}) else 1)"; then
      shimdir="${FRP_PYTHON_SHIM_DIR:-/usr/local/bin}"
      mkdir -p "$shimdir" 2>/dev/null || shimdir="${TMPDIR:-/tmp}/frp-python-shim"
      mkdir -p "$shimdir"
      ln -sfn "$(command -v "$candidate")" "$shimdir/python3"
      case ":$PATH:" in
        *":$shimdir:"*) ;;
        *) export PATH="$shimdir:$PATH" ;;
      esac
      hash -r 2>/dev/null || true
      return 0
    fi
  done
  return 1
}

frp_required_commands() {
  local role="${FRP_DEPENDENCY_ROLE:-client}"
  printf '%s\n' curl openssl python3 tar sha256sum timeout hostname install
  if [[ "$role" == server ]]; then
    printf '%s\n' ss
  fi
}

frp_collect_missing_commands() {
  local cmd
  MISSING_COMMANDS=()
  while IFS= read -r cmd; do
    [[ -n "$cmd" ]] || continue
    if [[ "$cmd" == "python3" ]]; then
      if ! frp_python_version_ok; then
        MISSING_COMMANDS+=("$cmd")
      fi
      continue
    fi
    if ! frp_command_exists "$cmd"; then
      MISSING_COMMANDS+=("$cmd")
    fi
  done < <(frp_required_commands)
}

frp_package_for_command() {
  local cmd="$1" pm="$2"
  case "$cmd" in
    curl) printf 'curl' ;;
    openssl) printf 'openssl' ;;
    python3)
      if frp_el8_family; then
        # EL8 platform python3 is 3.6; AppStream python39 satisfies the gate.
        printf 'python39'
      else
        printf 'python3'
      fi
      ;;
    tar) printf 'tar' ;;
    sha256sum|timeout|install) printf 'coreutils' ;;
    hostname) printf 'hostname' ;;
    ss|ip)
      if [[ "$pm" == apt ]]; then
        printf 'iproute2'
      else
        printf 'iproute'
      fi
      ;;
    nginx) printf 'nginx' ;;
    *)
      echo "ERROR: no package mapping for command: ${cmd}" >&2
      return 1
      ;;
  esac
}

frp_packages_for_missing() {
  local pm="$1" cmd pkg existing existing_pkg
  PACKAGES=(ca-certificates)
  for cmd in "${MISSING_COMMANDS[@]}"; do
    pkg="$(frp_package_for_command "$cmd" "$pm")"
    existing=0
    for existing_pkg in "${PACKAGES[@]}"; do
      if [[ "$existing_pkg" == "$pkg" ]]; then
        existing=1
        break
      fi
    done
    if (( existing == 0 )); then
      PACKAGES+=("$pkg")
    fi
  done
}

install_dependencies_apt() {
  local bin
  bin="$(frp_package_manager_bin apt-get)"
  export DEBIAN_FRONTEND=noninteractive
  "$bin" update
  "$bin" install -y --no-install-recommends "$@"
}

install_dependencies_dnf() {
  local bin
  bin="$(frp_package_manager_bin dnf)"
  "$bin" install -y "$@"
}

install_dependencies_yum() {
  local bin
  bin="$(frp_package_manager_bin yum)"
  "$bin" install -y "$@"
}

frp_print_missing_tools_error() {
  local cmd
  echo "ERROR: required tools are missing:" >&2
  for cmd in "${MISSING_COMMANDS[@]}"; do
    echo "  ${cmd}" >&2
  done
  echo >&2
  echo "Automatic dependency installation supports apt, dnf, and yum." >&2
  echo "Install the missing tools manually and run the installer again." >&2
}

ensure_dependencies() {
  frp_collect_missing_commands
  if ((${#MISSING_COMMANDS[@]} == 0)); then
    frp_prefer_newer_python || true
    return 0
  fi
  if [[ -z "${PACKAGE_MANAGER:-}" ]]; then
    frp_detect_package_manager
  fi
  if [[ -z "${PACKAGE_MANAGER:-}" ]]; then
    frp_print_missing_tools_error
    return 1
  fi
  frp_packages_for_missing "$PACKAGE_MANAGER"
  case "$PACKAGE_MANAGER" in
    apt) install_dependencies_apt "${PACKAGES[@]}" ;;
    dnf) install_dependencies_dnf "${PACKAGES[@]}" ;;
    yum) install_dependencies_yum "${PACKAGES[@]}" ;;
    *)
      echo "ERROR: unsupported package manager: ${PACKAGE_MANAGER}" >&2
      return 1
      ;;
  esac
  frp_prefer_newer_python || true
  frp_collect_missing_commands
  if ((${#MISSING_COMMANDS[@]} > 0)); then
    echo "ERROR: missing required command after dependency installation:" >&2
    local cmd
    for cmd in "${MISSING_COMMANDS[@]}"; do
      echo "  ${cmd}" >&2
    done
    return 1
  fi
}

frp_detect_internal_ip() {
  local ip=""
  if frp_command_exists hostname; then
    ip="$(frp_invoke hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "$ip" ]] && frp_command_exists ip; then
    ip="$(frp_invoke ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
  fi
  printf '%s' "$ip"
}

frp_short_hostname() {
  local h=""
  if [[ -n "${FRP_TEST_HOSTNAME:-}" ]]; then
    printf '%s' "$FRP_TEST_HOSTNAME"
    return 0
  fi
  if frp_command_exists hostname; then
    h="$(frp_invoke hostname -s 2>/dev/null || frp_invoke hostname 2>/dev/null || true)"
  fi
  if [[ -z "$h" ]]; then
    h="$(uname -n 2>/dev/null || true)"
  fi
  h="${h%%.*}"
  printf '%s' "$h"
}

# Parse `ss -lnt` with or without -H (Amazon Linux 2 iproute may lack --no-header).
frp_listening_tcp_ports_in_range() {
  local start="$1" end="$2" raw=""
  if ! frp_command_exists ss; then
    return 0
  fi
  raw="$(frp_invoke ss -H -lnt 2>/dev/null || frp_invoke ss -lnt 2>/dev/null || true)"
  printf '%s\n' "$raw" | awk -v s="$start" -v e="$end" '
    $1 ~ /^(State|Netid)$/ { next }
    {
      p=$4
      gsub(/\]$/, "", p)
      sub(/^.*:/, "", p)
      if (p ~ /^[0-9]+$/ && p+0>=s && p+0<=e) print p
    }
  ' | sort -nu | paste -sd, - 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Software-lifecycle helpers (install / update / uninstall)
# ---------------------------------------------------------------------------

FRP_BACKUP_KEEP="${FRP_BACKUP_KEEP:-5}"

if ! declare -F frp_emit_failure_class >/dev/null 2>&1; then
  frp_emit_failure_class() {
    local class="$1"
    printf 'FAILURE_CLASS=%s\n' "$class"
    printf 'FAILURE_CLASS=%s\n' "$class" >&2
  }
fi

frp_is_unsafe_delete_path() {
  local path="${1:-}"
  if [[ -z "$path" || "$path" == "/" || "$path" == "." || "$path" == ".." || "$path" == "//" ]]; then
    return 0
  fi
  case "$path" in
    /*) ;;
    *) return 0 ;;
  esac
  return 1
}

frp_path_has_symlink_component() {
  local path="${1:-}"
  local parent
  if [[ -L "$path" ]]; then
    return 0
  fi
  parent="${path%/*}"
  if [[ -n "$parent" && "$parent" != "$path" && -L "$parent" ]]; then
    return 0
  fi
  return 1
}

frp_require_safe_write_path() {
  local path="${1:-}"
  if frp_is_unsafe_delete_path "$path"; then
    echo "ERROR: refusing unsafe installation path" >&2
    frp_emit_failure_class PATH_DELETION_REFUSED
    return 1
  fi
  if [[ -e "$path" || -L "$path" ]] && frp_path_has_symlink_component "$path"; then
    echo "ERROR: refusing to write through a symlink: ${path}" >&2
    frp_emit_failure_class SYMLINK_REFUSED
    return 1
  fi
  local parent
  parent="${path%/*}"
  if [[ -n "$parent" && "$parent" != "$path" && ( -e "$parent" || -L "$parent" ) ]]; then
    if frp_path_has_symlink_component "$parent"; then
      echo "ERROR: refusing to write through a symlink parent: ${path}" >&2
      frp_emit_failure_class SYMLINK_REFUSED
      return 1
    fi
  fi
  return 0
}

frp_safe_rm_rf() {
  local path="${1:-}"
  if frp_is_unsafe_delete_path "$path"; then
    echo "ERROR: refusing unsafe recursive deletion" >&2
    frp_emit_failure_class PATH_DELETION_REFUSED
    return 1
  fi
  if [[ -L "$path" ]]; then
    echo "ERROR: refusing to recursively delete through a symlink" >&2
    frp_emit_failure_class SYMLINK_REFUSED
    return 1
  fi
  if [[ ! -e "$path" ]]; then
    return 0
  fi
  if [[ ! -d "$path" ]]; then
    echo "ERROR: refusing recursive deletion of a non-directory" >&2
    frp_emit_failure_class PATH_DELETION_REFUSED
    return 1
  fi
  rm -rf "$path"
}

frp_atomic_write() {
  local dest="$1" mode="${2:-0600}"
  local dir tmp
  frp_require_safe_write_path "$dest" || return 1
  dir="$(dirname "$dest")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.frp-write.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  if [[ ${EUID} -eq 0 ]]; then
    chown root:root "$tmp" 2>/dev/null || true
  fi
  mv -f "$tmp" "$dest"
}

frp_secure_mktemp_dir() {
  local dir
  dir="$(mktemp -d)"
  chmod 700 "$dir"
  printf '%s' "$dir"
}

frp_version_compare() {
  python3 - "$1" "$2" <<'PY'
import re, sys
def parse(v):
    text = (v or "").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", text):
        return None
    return tuple(int(x) for x in text.split("."))
a, b = parse(sys.argv[1]), parse(sys.argv[2])
if a is None or b is None:
    print("invalid")
    raise SystemExit(0)
if a > b:
    print("gt")
elif a < b:
    print("lt")
else:
    print("eq")
PY
}

frp_elf_arch_label() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if not path.is_file():
    print("missing")
    raise SystemExit(0)
data = path.read_bytes()
if len(data) < 20 or data[:4] != b"\x7fELF":
    print("non-elf")
    raise SystemExit(0)
endian = "little" if data[5] == 1 else "big"
machine = int.from_bytes(data[18:20], endian)
if machine == 62:
    print("amd64")
elif machine == 183:
    print("arm64")
else:
    print("other")
PY
}

frp_extract_frp_member() {
  local archive="$1" dest_dir="$2" member="$3"
  python3 - "$archive" "$dest_dir" "$member" <<'PY'
import os, sys, tarfile
from pathlib import Path

archive, dest_dir, member = sys.argv[1], sys.argv[2], sys.argv[3]
dest = Path(dest_dir)
dest.mkdir(parents=True, exist_ok=True)
out = dest / member

def unsafe(name):
    name = name.replace("\\", "/")
    if name.startswith("/") or name.startswith("../") or name == ".." or "/../" in name:
        return True
    if name.endswith("/.."):
        return True
    return False

found = None
try:
    tf = tarfile.open(archive, "r:*")
except tarfile.TarError:
    sys.stderr.write("ERROR: archive is not a valid tar file\n")
    raise SystemExit(1)
with tf:
    for info in tf.getmembers():
        name = info.name.replace("\\", "/")
        if unsafe(name):
            sys.stderr.write("ERROR: archive contains an unsafe path\n")
            raise SystemExit(1)
        if Path(name).name != member:
            continue
        if info.issym() or info.islnk():
            sys.stderr.write("ERROR: archive member %s is a link\n" % member)
            raise SystemExit(1)
        if not info.isfile():
            continue
        found = info
        break
    if found is None:
        sys.stderr.write("ERROR: archive did not contain expected file %s\n" % member)
        raise SystemExit(1)
    src = tf.extractfile(found)
    if src is None:
        sys.stderr.write("ERROR: failed to read archive member %s\n" % member)
        raise SystemExit(1)
    data = src.read()
tmp = dest / (".%s.extract" % member)
tmp.write_bytes(data)
os.chmod(str(tmp), 0o755)
tmp.replace(out)
print(str(out))
PY
}

frp_validate_frp_binary() {
  local bin="$1" expected_ver="$2" expected_arch="${3:-}"
  local elf ver
  [[ -f "$bin" ]] || {
    echo "ERROR: candidate binary is missing" >&2
    return 1
  }
  [[ -x "$bin" ]] || {
    echo "ERROR: candidate is not executable" >&2
    return 1
  }
  elf="$(frp_elf_arch_label "$bin")"
  if [[ "$elf" != "non-elf" && "$elf" != "missing" && -n "$expected_arch" && "$elf" != "$expected_arch" ]]; then
    echo "ERROR: candidate architecture (${elf}) does not match this host (${expected_arch})" >&2
    return 1
  fi
  ver="$(frp_parse_binary_version "$bin")"
  if [[ "$ver" != "$expected_ver" ]]; then
    echo "ERROR: candidate FRP version (${ver}) is not the pinned version (${expected_ver})" >&2
    return 1
  fi
  return 0
}

frp_prune_backup_dirs() {
  local root="$1" keep="${2:-$FRP_BACKUP_KEEP}"
  python3 - "$root" "$keep" <<'PY'
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

frp_txn_marker_path() {
  # Role-specific transaction markers prevent dual-role collision.
  # Optional arg / FRP_TXN_ROLE: server | client
  # Legacy shared update-pending.json is adopted explicitly; never guessed.
  local role="${1:-${FRP_TXN_ROLE:-}}"
  local root="${FRP_UPDATE_ROOT:-${FRP_DEPLOY_TEST_ROOT:-${FRP_SERVER_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-${FRP_UNINSTALL_TEST_ROOT:-}}}}}"
  local base dir canonical
  case "$role" in
    server) base="server-update-pending.json" ;;
    client) base="client-update-pending.json" ;;
    "")
      echo "ERROR: transaction marker role is required (server|client)" >&2
      return 1
      ;;
    *)
      echo "ERROR: unknown transaction marker role: $role" >&2
      return 1
      ;;
  esac
  if [[ -n "$root" ]]; then
    canonical="$(frp_platform_map_path /var/lib/frp-auto-deploy)"
    dir="${root}${canonical}"
  else
    dir="$(frp_platform_map_path /var/lib/frp-auto-deploy)"
  fi
  printf '%s/%s' "$dir" "$base"
}

frp_txn_legacy_marker_path() {
  local root="${FRP_UPDATE_ROOT:-${FRP_DEPLOY_TEST_ROOT:-${FRP_SERVER_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-${FRP_UNINSTALL_TEST_ROOT:-}}}}}"
  local p
  p="$(frp_platform_map_path /var/lib/frp-auto-deploy/update-pending.json)"
  if [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_txn_role_for_operation() {
  case "$1" in
    install|project-update|frp-update) printf 'server' ;;
    client-update|client-frp-update) printf 'client' ;;
    *) return 1 ;;
  esac
}

frp_txn_adopt_legacy_marker() {
  # Move legacy update-pending.json into the role-specific path when the
  # operation field unambiguously identifies the role. Fail closed otherwise.
  local role="${1:-${FRP_TXN_ROLE:-}}"
  local legacy target op
  [[ -n "$role" ]] || return 1
  legacy="$(frp_txn_legacy_marker_path)"
  [[ -f "$legacy" ]] || return 0
  target="$(frp_txn_marker_path "$role")" || return 1
  if [[ -f "$target" ]]; then
    echo "ERROR: both legacy and role-specific transaction markers exist; refusing to guess." >&2
    echo "FAILURE_CLASS=TXN_MARKER_AMBIGUOUS" >&2
    return 1
  fi
  op="$(python3 - "$legacy" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(str(data.get("operation") or "").strip())
PY
)"
  case "$op" in
    install|project-update|frp-update)
      if [[ "$role" != "server" ]]; then
        echo "ERROR: legacy transaction marker belongs to the server role; refusing client recovery." >&2
        echo "FAILURE_CLASS=TXN_MARKER_ROLE_MISMATCH" >&2
        return 1
      fi
      ;;
    client-update)
      if [[ "$role" != "client" ]]; then
        echo "ERROR: legacy transaction marker belongs to the client role; refusing server recovery." >&2
        echo "FAILURE_CLASS=TXN_MARKER_ROLE_MISMATCH" >&2
        return 1
      fi
      ;;
    *)
      echo "ERROR: legacy update-pending.json has ambiguous operation=${op:-unknown}; refusing to guess." >&2
      echo "FAILURE_CLASS=TXN_MARKER_AMBIGUOUS" >&2
      return 1
      ;;
  esac
  mv -f "$legacy" "$target"
}

frp_txn_write() {
  local operation="$1" phase="$2" previous="${3:-}" candidate="${4:-}"
  local marker dir tmp role
  if ! role="$(frp_txn_role_for_operation "$operation")"; then
    echo "ERROR: unknown transaction operation: $operation" >&2
    return 1
  fi
  FRP_TXN_ROLE="$role"
  export FRP_TXN_ROLE
  frp_txn_adopt_legacy_marker "$role" || return 1
  marker="$(frp_txn_marker_path "$role")" || return 1
  dir="$(dirname "$marker")"
  mkdir -p "$dir"
  chmod 700 "$dir" 2>/dev/null || true
  tmp="$(mktemp "${dir}/.update-pending.XXXXXX")"
  python3 - "$tmp" "$operation" "$phase" "$previous" "$candidate" \
    "${FRP_TXN_RELEASE_CHANNEL:-}" "${FRP_TXN_SOURCE_REF:-}" \
    "${FRP_TXN_BUNDLE_SHA256:-}" "${FRP_TXN_SNAPSHOT_PATH:-}" \
    "${FRP_TXN_MUTATION_STARTED:-true}" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path

def optional(value):
    value = str(value or "").strip()
    return value or None

record = {
    "schema_version": 2,
    "operation": sys.argv[2],
    "phase": sys.argv[3],
    "previous_version": sys.argv[4],
    "candidate_version": sys.argv[5],
    "started_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "mutation_started": sys.argv[10].lower() in ("1", "true", "yes"),
}
for key, raw in (
    ("release_channel", sys.argv[6]),
    ("source_ref", sys.argv[7]),
    ("bundle_sha256", sys.argv[8]),
    ("snapshot_path", sys.argv[9]),
):
    value = optional(raw)
    if value is not None:
        record[key] = value
Path(sys.argv[1]).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY
  chmod 0644 "$tmp"
  mv -f "$tmp" "$marker"
}

frp_txn_clear() {
  local role="${1:-${FRP_TXN_ROLE:-}}"
  local marker
  if [[ -z "$role" ]]; then
    echo "ERROR: transaction clear requires a role (server|client)" >&2
    return 1
  fi
  marker="$(frp_txn_marker_path "$role")" || return 1
  rm -f "$marker"
  # Never clear the other role's marker. Legacy shared marker is only removed
  # when it unambiguously belongs to this role.
  local legacy op
  legacy="$(frp_txn_legacy_marker_path)"
  if [[ -f "$legacy" ]]; then
    op="$(python3 - "$legacy" <<'PY'
import json, sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
print(str(data.get("operation") or "").strip())
PY
)"
    case "$op" in
      install|project-update|frp-update)
        [[ "$role" == "server" ]] && rm -f "$legacy"
        ;;
      client-update)
        [[ "$role" == "client" ]] && rm -f "$legacy"
        ;;
    esac
  fi
}

frp_audit_emit() {
  local event="$1" py=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_audit.py" ]]; then
    py="$BASE_DIR/lib/frp_audit.py"
  elif [[ -f /usr/local/lib/frp-auto-deploy/frp_audit.py ]]; then
    py=/usr/local/lib/frp-auto-deploy/frp_audit.py
  else
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    [[ -f "${here}/frp_audit.py" ]] && py="${here}/frp_audit.py"
  fi
  [[ -n "$py" && -f "$py" ]] || return 0
  python3 "$py" emit --event "$event" 2>/dev/null || true
}

frp_role_fs() {
  local p
  p="$(frp_platform_map_path "$1")"
  local root="${FRP_ROLE_TEST_ROOT:-${FRP_SERVER_TEST_ROOT:-${FRP_CLIENT_TEST_ROOT:-${FRP_UNINSTALL_TEST_ROOT:-${FRP_DEPLOY_TEST_ROOT:-${FRP_UPDATE_ROOT:-}}}}}}"
  if [[ -n "$root" ]]; then
    printf '%s' "${root}${p}"
  else
    printf '%s' "$p"
  fi
}

frp_detect_host_role() {
  local server_signals=0 client_signals=0
  local has_server_config=0 has_client_state=0
  FRP_HOST_ROLE=absent
  [[ -f "$(frp_role_fs /etc/frp-auto-deploy/config.json)" ]] && { has_server_config=1; server_signals=$((server_signals + 1)); }
  [[ -f "$(frp_role_fs /etc/frp/server_token)" ]] && server_signals=$((server_signals + 1))
  [[ -f "$(frp_role_fs /var/lib/frp-auto-deploy/registry.json)" ]] && server_signals=$((server_signals + 1))
  [[ -f "$(frp_role_fs /etc/frp/frps.toml)" ]] && server_signals=$((server_signals + 1))
  [[ -x "$(frp_role_fs /usr/local/bin/frps)" ]] && server_signals=$((server_signals + 1))
  [[ -x "$(frp_role_fs /usr/local/sbin/frp-create-client)" ]] && server_signals=$((server_signals + 1))
  [[ -f "$(frp_role_fs /etc/frp/client-state.json)" ]] && { has_client_state=1; client_signals=$((client_signals + 1)); }
  [[ -f "$(frp_role_fs /etc/frp/frpc.toml)" ]] && client_signals=$((client_signals + 1))
  [[ -f "$(frp_role_fs /etc/frp/client-identity.key)" ]] && client_signals=$((client_signals + 1))
  [[ -x "$(frp_role_fs /usr/local/bin/frpc)" ]] && client_signals=$((client_signals + 1))
  [[ -x "$(frp_role_fs /usr/local/bin/frp-client)" ]] && client_signals=$((client_signals + 1))
  if (( server_signals >= 2 && client_signals >= 2 )); then
    FRP_HOST_ROLE=both
  elif (( server_signals >= 2 )); then
    FRP_HOST_ROLE=server
  elif (( client_signals >= 2 )); then
    FRP_HOST_ROLE=client
  elif [[ "$has_server_config" == "1" ]]; then
    FRP_HOST_ROLE=server
  elif [[ "$has_client_state" == "1" ]]; then
    FRP_HOST_ROLE=client
  elif (( server_signals == 1 )); then
    FRP_HOST_ROLE=partial-server
  elif (( client_signals == 1 )); then
    FRP_HOST_ROLE=partial-client
  else
    FRP_HOST_ROLE=absent
  fi
}

# Load platform helpers after the common primitives they use are defined.
if [[ -z "${FRP_MACOS_LOADED:-}" ]]; then
  for _frp_macos_candidate in \
    "${_FRP_COMMON_DIR}/frp-macos.sh" \
    /usr/local/lib/frp-auto-deploy/frp-macos.sh \
    '/Library/Application Support/frp-auto-deploy/lib/frp-macos.sh'; do
    if [[ -f "$_frp_macos_candidate" ]]; then
      # shellcheck disable=SC1090
      . "$_frp_macos_candidate"
      break
    fi
  done
  unset _frp_macos_candidate
fi
