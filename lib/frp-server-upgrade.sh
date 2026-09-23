#!/usr/bin/env bash
# Safe, non-interactive management-software upgrade for an installed server.

FRP_SERVER_UPGRADE_BACKUP_KEEP="${FRP_SERVER_UPGRADE_BACKUP_KEEP:-5}"
# Any Python module imported by the allocator must be listed here so project
# updates and install restarts pick up runtime helper changes.
FRP_ALLOCATOR_RUNTIME_HELPERS=(
  frp_mgmt_auth.py
  frp_pki.py
  frp_client_registry.py
  frp_enrollment_lifecycle.py
  frp_zero_touch.py
  frp_audit.py
  drlink_runtime_policy.py
  drlink_control_db.py
  drlink_control_plane.py
  drlink_mgmt_sync.py
  drlink_upgrade_reconcile.py
  drlink_qualified_artifacts.py
)
# Long-running drlink-mcp-bridge import closure. A project update must restart
# the bridge when any of these files change; the process keeps them in memory.
# Launcher server/drlink-mcp-bridge.py loads lib/drlink_mcp_bridge.py, which
# imports drlink_ai_agent, drlink_control_db, drlink_control_plane,
# frp_client_registry, and drlink_v24. OAuth/MCP request paths in those modules
# also import drlink_mcp_tls, frp_server_config, drlink_mgmt_sync, and
# drlink_upgrade_reconcile.
FRP_MCP_BRIDGE_RUNTIME_HELPERS=(
  drlink_mcp_bridge.py
  drlink-mcp-bridge.py
  drlink_ai_agent.py
  drlink_control_db.py
  drlink_control_plane.py
  frp_client_registry.py
  drlink_v24.py
  drlink_mcp_tls.py
  frp_server_config.py
  drlink_mgmt_sync.py
  drlink_upgrade_reconcile.py
)
_FRP_UPGRADE_MUTATION_STARTED=0
_FRP_UPGRADE_ROLLBACK_DONE=0
_FRP_UPGRADE_ROLLBACK_RC=0
_FRP_UPGRADE_IN_ROLLBACK=0
_FRP_UPGRADE_ERRTRACE_WAS=0

_frp_project_files_py() {
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_project_files.py" ]]; then
    printf '%s' "$BASE_DIR/lib/frp_project_files.py"
  elif [[ -f /usr/local/lib/drlink/frp_project_files.py ]]; then
    printf '%s' /usr/local/lib/drlink/frp_project_files.py
  else
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    printf '%s' "${here}/frp_project_files.py"
  fi
}

frp_server_upgrade_destinations() {
  local extra=()
  if frp_server_upgrade_is_single443; then
    extra+=(--single443)
  fi
  if [[ -n "${1:-}" ]]; then
    extra+=(--source "$1")
  elif [[ -n "${BASE_DIR:-}" ]]; then
    extra+=(--source "$BASE_DIR")
  fi
  python3 "$(_frp_project_files_py)" destinations "${extra[@]}"
}

frp_install_qualified_artifacts_from() {
  local source="${1:-${BASE_DIR:-}}"
  local dest agent_linux agent_windows py
  dest="$(frp_server_fs /usr/local/share/drlink/artifacts)"
  py="${source}/lib/drlink_qualified_artifacts.py"
  if [[ ! -f "$py" ]]; then
    py="$(frp_server_fs /usr/local/lib/drlink/drlink_qualified_artifacts.py)"
  fi
  agent_linux=""
  agent_windows=""
  if [[ -f "${source}/dist/bootstrap-client.sh" ]]; then
    agent_linux="${source}/dist/bootstrap-client.sh"
  elif [[ -f "${source}/artifacts/agent/bootstrap-client.sh" ]]; then
    agent_linux="${source}/artifacts/agent/bootstrap-client.sh"
  fi
  if [[ -f "${source}/dist/bootstrap-client.ps1" ]]; then
    agent_windows="${source}/dist/bootstrap-client.ps1"
  elif [[ -f "${source}/artifacts/agent/bootstrap-client.ps1" ]]; then
    agent_windows="${source}/artifacts/agent/bootstrap-client.ps1"
  fi
  if [[ ! -f "$py" || -z "$agent_linux" || -z "$agent_windows" ]]; then
    python3 "${py:-$(frp_qualified_artifacts_py)}" missing-error \
      --platform linux --architecture any >&2 || true
    echo "No changes were applied." >&2
    return 1
  fi
  frp_infer_expected_source_ref_from_git_source "$source"
  frp_infer_expected_source_from_release_manifest "$source"
  python3 "$py" install \
    --source "$source" --dest "$dest" \
    --agent-linux "$agent_linux" --agent-windows "$agent_windows"
}

frp_server_upgrade_is_single443() {
  python3 - "$(frp_server_fs /etc/drlink/config.json)" <<'PY'
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if data.get("deployment_mode", "direct") == "single443" else 1)
PY
}

frp_load_installed_server_runtime() {
  # Persisted installed-server configuration. Distinct from installer input globals.
  local config version_file line
  config="$(frp_server_fs /etc/drlink/config.json)"
  version_file="$(frp_server_fs /etc/drlink/version)"
  [[ -f "$config" ]] || {
    echo "ERROR: installed server configuration is missing" >&2
    return 1
  }
  while IFS= read -r line; do
    case "$line" in
      FRP_DEPLOYMENT_MODE=*|FRP_PUBLIC_HOST=*|FRP_CONTROL_PUBLIC_PORT=*|FRP_CONTROL_LISTEN_PORT=*|FRP_ALLOCATOR_PUBLIC_URL=*|FRP_ALLOCATOR_LISTEN_PORT=*|FRP_INSTALLED_CA_CERT=*|CA_FINGERPRINT=*|FRP_INSTALLED_PROJECT_VERSION=*|FRP_INSTALLED_RELEASE_CHANNEL=*|FRP_INSTALLED_SOURCE_REF=*|FRP_INSTALLED_BUNDLE_SHA256=*)
        printf -v "${line%%=*}" '%s' "${line#*=}"
        ;;
    esac
  done < <(
    python3 - "$config" "$version_file" "$(frp_pki_dir)/ca.crt" "${BASE_DIR:-}/lib/frp_pki.py" <<'PY'
import json, sys
from pathlib import Path

config_path, version_path, ca_path, pki_mod = sys.argv[1:]
data = json.loads(Path(config_path).read_text(encoding="utf-8"))
values = {}
if Path(version_path).is_file():
    for line in Path(version_path).read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

def emit(key, value):
    print("%s=%s" % (key, value if value is not None else ""))

emit("FRP_DEPLOYMENT_MODE", data.get("deployment_mode") or "direct")
emit("FRP_PUBLIC_HOST", data.get("public_host") or data.get("public_ip") or "")
emit("FRP_CONTROL_PUBLIC_PORT", data.get("frp_control_public_port") or "")
emit("FRP_CONTROL_LISTEN_PORT", data.get("frp_control_listen_port") or "")
emit("FRP_ALLOCATOR_PUBLIC_URL", data.get("allocator_public_url") or "")
emit(
    "FRP_ALLOCATOR_LISTEN_PORT",
    data.get("allocator_listen_port", data.get("listen_port", 6099)),
)
ca = data.get("tls_ca_cert") or ca_path
emit("FRP_INSTALLED_CA_CERT", ca)
fp = ""
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("frp_pki", pki_mod)
    if spec and spec.loader and Path(pki_mod).is_file() and Path(ca).is_file():
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fp = mod.fingerprint_from_cert_file(ca)
except Exception:
    fp = ""
emit("CA_FINGERPRINT", fp)
emit("FRP_INSTALLED_PROJECT_VERSION", values.get("PROJECT_VERSION", ""))
emit("FRP_INSTALLED_RELEASE_CHANNEL", values.get("RELEASE_CHANNEL", ""))
emit("FRP_INSTALLED_SOURCE_REF", values.get("SOURCE_REF", ""))
emit("FRP_INSTALLED_BUNDLE_SHA256", values.get("BUNDLE_SHA256", ""))
PY
  )
  if [[ -z "${FRP_PUBLIC_HOST:-}" ]]; then
    echo "ERROR: persisted public_host is missing from the installed configuration" >&2
    return 1
  fi
  if [[ -z "${FRP_CONTROL_PUBLIC_PORT:-}" ]]; then
    echo "ERROR: persisted frp_control_public_port is missing from the installed configuration" >&2
    return 1
  fi
  FRP_INSTALLED_RUNTIME_LOADED=1
  export FRP_DEPLOYMENT_MODE FRP_PUBLIC_HOST FRP_CONTROL_PUBLIC_PORT \
    FRP_CONTROL_LISTEN_PORT FRP_ALLOCATOR_PUBLIC_URL FRP_ALLOCATOR_LISTEN_PORT \
    FRP_INSTALLED_CA_CERT CA_FINGERPRINT
}

frp_server_upgrade_tree_digest() {
  python3 - "$@" <<'PY'
import hashlib
import sys
from pathlib import Path

h = hashlib.sha256()
for raw in sorted(sys.argv[1:]):
    path = Path(raw)
    h.update((raw + "\0").encode())
    if path.is_file():
        h.update(b"F")
        h.update(path.read_bytes())
    elif path.is_dir():
        h.update(b"D")
        for child in sorted(p for p in path.rglob("*") if p.is_file()):
            h.update((str(child.relative_to(path)) + "\0").encode())
            h.update(child.read_bytes())
    else:
        h.update(b"M")
print(h.hexdigest())
PY
}

frp_server_local_source_tree_digest() {
  # Local --source build identity only. Hash staged content and paths relative
  # to the staging root so a new temporary directory does not change identity.
  # Protected-state comparisons keep frp_server_upgrade_tree_digest().
  python3 - "$@" <<'PY'
import hashlib
import sys
from pathlib import Path

h = hashlib.sha256()
for raw in sys.argv[1:]:
    path = Path(raw)
    if not path.is_dir():
        raise SystemExit("local-source digest requires a staging directory")
    h.update(b"D")
    files = sorted(
        (p for p in path.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(path).as_posix(),
    )
    for child in files:
        rel = child.relative_to(path).as_posix()
        h.update((rel + "\0").encode())
        h.update(child.read_bytes())
print(h.hexdigest())
PY
}

frp_server_upgrade_preserved_digest() {
  # Include every manifest "protected" path under /var/lib/drlink plus
  # runtime binaries/config that must survive project-update. Deriving the
  # state-file set from the manifest keeps newly added protected resources
  # covered automatically.
  local -a paths=(
    "$(frp_server_fs /usr/local/bin/frps)"
    "$(frp_server_fs /etc/frp/frps.toml)"
    "$(frp_server_fs /etc/frp/server_token)"
    "$(frp_server_fs /etc/drlink/config.json)"
    "$(frp_server_fs /etc/drlink/pki)"
    "$(frp_server_fs /var/lib/drlink/enrollments)"
    "$(frp_server_fs /var/lib/drlink/bootstrap)"
    "$(frp_server_fs /var/lib/drlink/nginx-ownership)"
  )
  local manifest_mod=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_project_files.py" ]]; then
    manifest_mod="$BASE_DIR/lib/frp_project_files.py"
  elif [[ -f "$(frp_server_fs /usr/local/lib/drlink/frp_project_files.py)" ]]; then
    manifest_mod="$(frp_server_fs /usr/local/lib/drlink/frp_project_files.py)"
  fi
  if [[ -n "$manifest_mod" ]]; then
    while IFS= read -r rel; do
      [[ -n "$rel" ]] || continue
      paths+=("$(frp_server_fs "/$rel")")
    done < <(python3 - "$manifest_mod" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("frp_project_files", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for rel in mod.protected_exact():
    print(rel)
PY
)
  else
    paths+=(
      "$(frp_server_fs /var/lib/drlink/registry.json)"
      "$(frp_server_fs /var/lib/drlink/access-control.json)"
      "$(frp_server_fs /var/lib/drlink/egress-control.json)"
      "$(frp_server_fs /var/lib/drlink/service-profiles.json)"
    )
  fi
  frp_server_upgrade_tree_digest "${paths[@]}"
}

frp_server_upgrade_allocator_port() {
  if [[ -n "${FRP_ALLOCATOR_LISTEN_PORT:-}" ]]; then
    printf '%s' "$FRP_ALLOCATOR_LISTEN_PORT"
    return 0
  fi
  python3 - "$(frp_server_fs /etc/drlink/config.json)" <<'PY'
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    value = data.get("allocator_listen_port", data.get("listen_port", 6099))
    print(int(value))
except Exception:
    print(6099)
PY
}

frp_server_upgrade_validate_source_metadata() {
  local source="$1"
  local expected_ref="${2:-${FRP_EXPECTED_SOURCE_REF:-}}"
  local expected_channel="${3:-${FRP_EXPECTED_RELEASE_CHANNEL:-}}"
  frp_validate_release_source_metadata "$source" "$expected_ref" "$expected_channel"
}

frp_server_display_or_unknown() {
  local v="${1:-}"
  if [[ -z "$v" ]]; then
    printf '%s' "unknown"
  else
    printf '%s' "$v"
  fi
}

frp_server_verified_bundle_sha256() {
  # Production remote identity: SHA256SUMS digest passed as FRP_BUNDLE_SHA256.
  # A self-hash of the running candidate is not external verification.
  local digest=""
  if [[ "${FRP_BUNDLE_SHA256:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    digest="$(printf '%s' "$FRP_BUNDLE_SHA256" | tr '[:upper:]' '[:lower:]')"
    printf '%s' "$digest"
    return 0
  fi
  return 1
}

frp_server_target_build_identity() {
  local staged="$1" digest=""
  if digest="$(frp_server_verified_bundle_sha256)"; then
    printf '%s' "$digest"
    return 0
  fi
  # Local --source (tests/development): staged project-tree digest is
  # build identity only. It is not a substitute for SHA256SUMS verification.
  frp_server_local_source_tree_digest "$staged"
}

frp_server_report_identity() {
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

frp_server_upgrade_stage() {
  local source="$1" staged="$2" rel mode src
  mkdir -p "$staged"
  while IFS=: read -r rel mode src; do
    [[ -f "${source}/${src}" ]] || {
      echo "ERROR: update source is missing ${src}" >&2
      return 1
    }
    mkdir -p "$(dirname "${staged}/${rel}")"
    install -m "$mode" "${source}/${src}" "${staged}/${rel}"
  done < <(frp_server_upgrade_destinations "$source")
}

frp_server_upgrade_validate_staged() {
  local staged="$1" file extra=()
  if frp_server_upgrade_is_single443; then
    extra+=(--single443)
  fi
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    bash -n "$file" || return 1
  done < <(python3 "$(_frp_project_files_py)" validate-list --kind bash --staged "$staged" "${extra[@]}")
  mapfile -t _frp_py_files < <(python3 "$(_frp_project_files_py)" validate-list --kind python --staged "$staged" "${extra[@]}")
  if [[ "${#_frp_py_files[@]}" -gt 0 ]]; then
    python3 -m py_compile "${_frp_py_files[@]}" || return 1
  fi
  find "$staged" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  if [[ "${FRP_SERVER_UPGRADE_HOOK_FAIL:-}" == "validate" ]]; then
    echo "ERROR: simulated staged update validation failure" >&2
    return 1
  fi
}

frp_server_upgrade_changed() {
  local staged="$1" rel="$2"
  [[ "$(frp_file_sha256 "${staged}/${rel}")" != \
     "$(frp_file_sha256 "$(frp_server_fs "/${rel}")")" ]]
}

# True when the unit has not loaded the current file bytes.
# A missing stamp means a process started before generation tracking, which
# is the stale public runtime this update must replace. Matching bytes are
# current even when the install rewrote the file and refreshed its mtime.
frp_server_unit_runtime_stale() {
  local unit="$1" file="$2" stamp got want
  [[ -f "$file" ]] || return 1
  if ! frp_server_skip_systemd && ! frp_server_test_mode; then
    if ! frp_server_systemctl is-active --quiet "$unit"; then
      return 0
    fi
  fi
  stamp="$(frp_server_fs "/var/lib/drlink/runtime-active/${unit}.sha")"
  [[ -f "$stamp" ]] || return 0
  got="$(tr -d '[:space:]' <"$stamp")"
  want="$(frp_file_sha256 "$file")"
  [[ -n "$got" && "$got" == "$want" ]] && return 1
  return 0
}

# Regenerate the project-owned single-443 frontend from the current generator.
# Activate only after validation. Identical output does not reload nginx unless
# the running frontend is older than the config it should be serving.
frp_server_upgrade_converge_frontend() {
  local live candidate
  frp_server_upgrade_is_single443 || return 0
  if ! declare -F write_frontend_config >/dev/null 2>&1; then
    echo "ERROR: frontend generator is not available" >&2
    return 1
  fi
  live="$(frp_server_fs /etc/drlink/frontend.conf)"
  candidate="$(mktemp)"
  if ! write_frontend_config "$candidate"; then
    rm -f "$candidate"
    echo "ERROR: frontend configuration could not be generated" >&2
    return 1
  fi
  if [[ -f "$live" ]] && cmp -s "$candidate" "$live"; then
    rm -f "$candidate"
    if frp_server_unit_runtime_stale drlink-frontend "$live"; then
      restart_frontend=1
    fi
    return 0
  fi
  if ! frp_frontend_validate_config "$candidate"; then
    rm -f "$candidate"
    echo "ERROR: generated frontend configuration is invalid; it was not activated" >&2
    return 1
  fi
  frp_atomic_install "$candidate" "$live" 0600 || {
    rm -f "$candidate"
    return 1
  }
  rm -f "$candidate"
  restart_frontend=1
  return 0
}

frp_server_upgrade_post_mutation_guard() {
  [[ "${FRP_SERVER_UPGRADE_HOOK_FAIL:-}" == "unbound-after-install" ]] || return 0
  echo "ERROR: simulated unexpected post-mutation abort" >&2
  return 1
}

frp_server_upgrade_install_staged() {
  local staged="$1" rel mode src count=0
  while IFS=: read -r rel mode src; do
    frp_atomic_install "${staged}/${rel}" "$(frp_server_fs "/${rel}")" "$mode" || return 1
    count=$((count + 1))
    if [[ "$count" -eq 1 && "${FRP_SERVER_UPGRADE_HOOK_FAIL:-}" == "install" ]]; then
      echo "ERROR: simulated project file install failure" >&2
      return 1
    fi
  done < <(frp_server_upgrade_destinations)
}

frp_server_upgrade_verify_restored() {
  local snapshot="$1"
  if [[ "${FRP_SERVER_UPGRADE_HOOK_ROLLBACK_FILES:-}" == "1" ]]; then
    echo "ERROR: simulated snapshot file restore verification failure" >&2
    return 1
  fi
  python3 - "$snapshot" "$(frp_server_snapshot_root)" <<'PY'
import json, sys
from pathlib import Path
snap, root = Path(sys.argv[1]), Path(sys.argv[2])
meta = json.loads((snap / "metadata.json").read_text(encoding="utf-8"))
for item in meta.get("present") or []:
    rel = item.get("path") or ""
    if not rel:
        continue
    live = root / rel
    src = snap / "files" / rel
    if not src.is_file() or not live.is_file() or live.read_bytes() != src.read_bytes():
        sys.stderr.write("ERROR: restored project file does not match snapshot: %s\n" % rel)
        raise SystemExit(1)
for rel in meta.get("absent") or []:
    live = root / rel
    if live.is_file() or live.is_symlink():
        sys.stderr.write("ERROR: snapshot-absent project file is still present: %s\n" % rel)
        raise SystemExit(1)
PY
}

frp_server_upgrade_verify_rollback_health() {
  if [[ "${FRP_SERVER_UPGRADE_HOOK_ROLLBACK_HEALTH:-}" == "1" ]]; then
    echo "ERROR: simulated rollback health verification failure" >&2
    return 1
  fi
  if frp_server_skip_systemd || frp_server_test_mode; then
    return 0
  fi
  frp_server_health_frps || return 1
  frp_server_health_allocator "$(frp_server_upgrade_allocator_port)" || return 1
  frp_server_health_access || return 1
  if [[ -f "$(frp_server_fs /etc/systemd/system/drlink-mcp-bridge.service)" ]]; then
    frp_server_health_mcp_bridge || return 1
  fi
  if declare -F frp_server_health_egress >/dev/null 2>&1; then
    frp_server_health_egress || return 1
  fi
  if declare -F frp_server_health_tcp_egress >/dev/null 2>&1; then
    if [[ -f "$(frp_server_fs /etc/systemd/system/drlink-tcp-egress.service)" ]]; then
      frp_server_health_tcp_egress || return 1
    fi
  elif [[ -f "$(frp_server_fs /etc/systemd/system/drlink-tcp-egress.service)" ]]; then
    frp_wait_unit_active drlink-tcp-egress || return 1
  fi
  if frp_server_upgrade_is_single443; then
    frp_server_health_frontend || return 1
  fi
}

_frp_server_upgrade_err() {
  local ec=$?
  if [[ "${_FRP_UPGRADE_MUTATION_STARTED:-0}" == "1" && \
        "${_FRP_UPGRADE_IN_ROLLBACK:-0}" != "1" && \
        "${_FRP_UPGRADE_ROLLBACK_DONE:-0}" != "1" ]]; then
    frp_server_upgrade_rollback "${FRP_INSTALL_SNAPSHOT:-}" || true
  fi
  return "$ec"
}

frp_server_upgrade_restore_snapshot_files() {
  # File-only restore for project-update rollback. Avoid --apply-services here:
  # mid-upgrade unit state is often transitional on live systemd hosts and can
  # fail strict enable/active replay even when files restore cleanly. Health is
  # re-checked separately after an explicit unit restart.
  local dest="${1:-${FRP_INSTALL_SNAPSHOT:-}}" py
  [[ -n "$dest" && -d "$dest" ]] || return 0
  if [[ "${FRP_SERVER_UPGRADE_HOOK_ROLLBACK_SYSTEMD:-}" == "1" ]]; then
    echo "ERROR: simulated systemd service-state restoration failure" >&2
    return 1
  fi
  py=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_install_txn.py" ]]; then
    py="$BASE_DIR/lib/frp_install_txn.py"
  else
    py="$(frp_server_fs /usr/local/lib/drlink/frp_install_txn.py)"
  fi
  python3 "$py" restore --root "$(frp_server_snapshot_root)" --dest "$dest" || return 1
  if ! frp_server_skip_systemd && ! frp_server_test_mode; then
    frp_server_systemctl daemon-reload || true
  fi
  # Restart every project-owned runtime that may already be running post-cutover
  # code, so disk restore cannot leave old files with new in-memory processes.
  # Test mode records the restart and refreshes the runtime generation stamp.
  frp_server_restart_unit drlink-access || return 1
  frp_server_restart_unit drlink-egress || return 1
  if [[ -f "$(frp_server_fs /etc/systemd/system/drlink-tcp-egress.service)" ]]; then
    frp_server_restart_unit drlink-tcp-egress || return 1
  fi
  frp_server_restart_unit drlink-server || return 1
  frp_server_restart_unit drlink-allocator || return 1
  if [[ -f "$(frp_server_fs /etc/systemd/system/drlink-mcp-bridge.service)" ]]; then
    frp_server_restart_unit drlink-mcp-bridge || return 1
  fi
  if frp_server_upgrade_is_single443; then
    frp_server_restart_unit drlink-frontend || return 1
  fi
  return 0
}

frp_server_upgrade_rollback() {
  local snapshot="$1"
  if [[ "${_FRP_UPGRADE_ROLLBACK_DONE:-0}" == "1" ]]; then
    return "${_FRP_UPGRADE_ROLLBACK_RC:-1}"
  fi
  if [[ "${_FRP_UPGRADE_IN_ROLLBACK:-0}" == "1" ]]; then
    return 1
  fi
  _FRP_UPGRADE_IN_ROLLBACK=1
  FRP_INSTALL_SNAPSHOT="$snapshot"
  if ! frp_server_upgrade_restore_snapshot_files "$snapshot"; then
    echo "UPGRADE_ROLLBACK=FAIL"
    echo "RECOVERY_REQUIRED=YES"
    frp_emit_update_rollback_recovery_guidance
    echo "LIVE_PROJECT_FILES_RESTORED=NO"
    echo "PENDING_MARKER_CLEARED=NO"
    _FRP_UPGRADE_ROLLBACK_RC=1
    _FRP_UPGRADE_ROLLBACK_DONE=1
    _FRP_UPGRADE_IN_ROLLBACK=0
    return 1
  fi
  if ! frp_server_upgrade_verify_restored "$snapshot"; then
    echo "UPGRADE_ROLLBACK=FAIL"
    echo "RECOVERY_REQUIRED=YES"
    frp_emit_update_rollback_recovery_guidance
    echo "LIVE_PROJECT_FILES_RESTORED=NO"
    echo "PENDING_MARKER_CLEARED=NO"
    _FRP_UPGRADE_ROLLBACK_RC=1
    _FRP_UPGRADE_ROLLBACK_DONE=1
    _FRP_UPGRADE_IN_ROLLBACK=0
    return 1
  fi
  if ! frp_server_upgrade_verify_rollback_health; then
    echo "UPGRADE_ROLLBACK=FAIL"
    echo "RECOVERY_REQUIRED=YES"
    frp_emit_update_rollback_recovery_guidance
    echo "LIVE_PROJECT_FILES_RESTORED=YES"
    echo "PENDING_MARKER_CLEARED=NO"
    _FRP_UPGRADE_ROLLBACK_RC=1
    _FRP_UPGRADE_ROLLBACK_DONE=1
    _FRP_UPGRADE_IN_ROLLBACK=0
    return 1
  fi
  frp_txn_clear server
  echo "LIVE_PROJECT_FILES_RESTORED=YES"
  echo "PENDING_MARKER_CLEARED=YES"
  echo "UPGRADE_ROLLBACK=PASS"
  _FRP_UPGRADE_ROLLBACK_RC=0
  _FRP_UPGRADE_ROLLBACK_DONE=1
  _FRP_UPGRADE_IN_ROLLBACK=0
  return 0
}

frp_server_upgrade_precheck_egress_port() {
  # Fail closed before mutation if Egress listen is owned by a published service.
  local cfg_file registry_file
  cfg_file="$(frp_server_fs /etc/drlink/config.json)"
  registry_file="$(frp_server_fs /var/lib/drlink/registry.json)"
  [[ -f "$cfg_file" && -f "$registry_file" ]] || return 0
  local infra_mod=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_infrastructure_ports.py" ]]; then
    infra_mod="$BASE_DIR/lib/frp_infrastructure_ports.py"
  else
    infra_mod="$(frp_server_fs /usr/local/lib/drlink/frp_infrastructure_ports.py)"
  fi
  [[ -f "$infra_mod" ]] || return 0
  python3 - "$cfg_file" "$registry_file" "$infra_mod" <<'PY'
import importlib.util, json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
registry = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
spec = importlib.util.spec_from_file_location("frp_infrastructure_ports", sys.argv[3])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    mod.assert_egress_not_owned_by_service(cfg, registry)
except Exception as exc:
    print("ERROR: %s" % exc, file=sys.stderr)
    raise SystemExit(1)
PY
}

frp_server_upgrade_ensure_egress() {
  # Bootstrap Controlled Egress state/unit on upgrades from pre-egress installs.
  local egress_file cfg_file unit_file
  egress_file="$(frp_server_fs /var/lib/drlink/egress-control.json)"
  cfg_file="$(frp_server_fs /etc/drlink/config.json)"
  unit_file="$(frp_server_fs /etc/systemd/system/drlink-egress.service)"
  if [[ ! -f "$egress_file" ]]; then
    local mod=""
    if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_egress_control.py" ]]; then
      mod="$BASE_DIR/lib/frp_egress_control.py"
    else
      mod="$(frp_server_fs /usr/local/lib/drlink/frp_egress_control.py)"
    fi
    python3 - "$egress_file" "$mod" <<'PY' || return 1
import importlib.util, sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.save_egress_state(mod.empty_egress_state(), path=path)
PY
    chmod 600 "$egress_file"
  else
    # Persist v1/v2 → current schema on upgrade so Fixed TCP / doctor see schema v3.
    local mod=""
    if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_egress_control.py" ]]; then
      mod="$BASE_DIR/lib/frp_egress_control.py"
    else
      mod="$(frp_server_fs /usr/local/lib/drlink/frp_egress_control.py)"
    fi
    if [[ -f "$mod" ]]; then
      python3 - "$egress_file" "$mod" <<'PY' || return 1
import importlib.util, sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
# load_egress_state migrates and persists under lock when schema < current.
state = mod.load_egress_state(path=path, persist_migration=True)
print("EGRESS_SCHEMA=%s" % state.get("schema_version"))
PY
    fi
  fi
  if [[ -f "$cfg_file" ]]; then
    python3 - "$cfg_file" <<'PY' || true
import json, sys, tempfile, os
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text(encoding="utf-8"))
changed = False
defaults = {
    "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
    "egress_listen_addr": "0.0.0.0",
    "egress_listen_port": 6102,
}
for key, value in defaults.items():
    if key not in cfg or cfg.get(key) in (None, ""):
        cfg[key] = value
        changed = True
if changed:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
PY
  fi
  # Re-apply egress readability after any 0600 rewrite of config/policy.
  local eg_mod=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_egress_control.py" ]]; then
    eg_mod="$BASE_DIR/lib/frp_egress_control.py"
  else
    eg_mod="$(frp_server_fs /usr/local/lib/drlink/frp_egress_control.py)"
  fi
  if [[ -f "$eg_mod" ]]; then
    python3 - "$eg_mod" "$cfg_file" "$egress_file" <<'PY' || true
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cfg = Path(sys.argv[2])
control = Path(sys.argv[3])
mod.reapply_egress_runtime_permissions(
    config_path=cfg if cfg.is_file() else None,
    control_path=control if control.is_file() else None,
    parents=True,
)
PY
  fi
  if [[ -f "$unit_file" ]] && ! frp_server_skip_systemd && ! frp_server_test_mode; then
    frp_server_systemctl enable drlink-egress >/dev/null || return 1
  elif [[ -f "$unit_file" ]]; then
    frp_server_record_action "enable drlink-egress"
  fi
  local tcp_unit
  tcp_unit="$(frp_server_fs /etc/systemd/system/drlink-tcp-egress.service)"
  if [[ -f "$tcp_unit" ]] && ! frp_server_skip_systemd && ! frp_server_test_mode; then
    frp_server_systemctl enable drlink-tcp-egress >/dev/null || return 1
  elif [[ -f "$tcp_unit" ]]; then
    frp_server_record_action "enable drlink-tcp-egress"
  fi
  return 0
}

frp_server_upgrade_ensure_control_plane() {
  # Bootstrap SQLite control-plane authority on upgrades from pre-SQLite installs.
  # Fresh installs initialize drlink.db in install-server.sh; project-update must
  # do the same before access/egress health checks expect authority=sqlite.
  local cfg_file db_file db_mod plane_mod created=0
  cfg_file="$(frp_server_fs /etc/drlink/config.json)"
  db_file="$(frp_server_fs /var/lib/drlink/drlink.db)"
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/drlink_control_db.py" ]]; then
    db_mod="$BASE_DIR/lib/drlink_control_db.py"
    plane_mod="$BASE_DIR/lib/drlink_control_plane.py"
  else
    db_mod="$(frp_server_fs /usr/local/lib/drlink/drlink_control_db.py)"
    plane_mod="$(frp_server_fs /usr/local/lib/drlink/drlink_control_plane.py)"
  fi
  [[ -f "$db_mod" && -f "$plane_mod" ]] || {
    echo "ERROR: control-plane modules missing from update source" >&2
    return 1
  }
  if [[ ! -f "$db_file" ]]; then
    created=1
  fi
  python3 - "$db_file" "$db_mod" "$plane_mod" <<'PY' || return 1
import importlib.util
import sys
from pathlib import Path

db_path = Path(sys.argv[1])
db_mod = Path(sys.argv[2])
plane_mod = Path(sys.argv[3])
lib_dir = str(db_mod.parent)
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)
spec = importlib.util.spec_from_file_location("drlink_control_db", str(db_mod))
db = importlib.util.module_from_spec(spec)
sys.modules["drlink_control_db"] = db
spec.loader.exec_module(db)
# <ROOT>/var/lib/drlink/drlink.db → <ROOT>  (real FS: / ; staging: test root)
deploy = db.deploy_root_from_db_path(db_path)
spec = importlib.util.spec_from_file_location("drlink_control_plane", str(plane_mod))
plane_mod_obj = importlib.util.module_from_spec(spec)
sys.modules["drlink_control_plane"] = plane_mod_obj
spec.loader.exec_module(plane_mod_obj)
plane = plane_mod_obj.ControlPlane(str(deploy))
try:
    st = plane.status()
    if not st.get("db_healthy"):
        raise SystemExit("control DB unhealthy after init")
    # Reconcile existing FRP registry clients into canonical SQLite (idempotent).
    registry_live = Path(str(deploy)) / "var/lib/drlink/runtime/client-inventory.json"
    registry_legacy = Path(str(deploy)) / "var/lib/drlink/registry.json"
    recon_mod = Path(sys.argv[3]).parent / "drlink_upgrade_reconcile.py"
    if recon_mod.is_file() and (registry_live.is_file() or registry_legacy.is_file()):
        spec = importlib.util.spec_from_file_location("drlink_upgrade_reconcile", str(recon_mod))
        ur = importlib.util.module_from_spec(spec)
        sys.modules["drlink_upgrade_reconcile"] = ur
        spec.loader.exec_module(ur)
        rec = ur.reconcile_control_plane(plane, root=str(deploy), connected=False)
        if rec.get("ok") and rec.get("applied"):
            print("CONTROL_DB_RECONCILED clients=%s hosts=%s" % (
                (rec.get("after") or {}).get("sqlite_clients"),
                (rec.get("after") or {}).get("managed_hosts"),
            ))
        elif rec.get("ok") and rec.get("skipped"):
            print("CONTROL_DB_RECONCILE_SKIPPED")
        elif not rec.get("ok"):
            print("CONTROL_DB_RECONCILE_WARNING %s" % rec.get("error"))
    st = plane.status()
    print("CONTROL_PLANE_ROOT=%s" % deploy)
    print("CONTROL_DB_OK revision=%s mismatch=%s clients=%s" % (
        st.get("revision"), st.get("mismatch"), st.get("clients")))
finally:
    plane.close()
PY
  chmod 600 "$db_file" 2>/dev/null || true
  if [[ -f "$cfg_file" ]]; then
    python3 - "$cfg_file" <<'PY' || true
import json, os, sys, tempfile
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads(path.read_text(encoding="utf-8"))
changed = False
defaults = {
    "registry_file": "/var/lib/drlink/runtime/client-inventory.json",
    "control_db_file": "/var/lib/drlink/drlink.db",
    "egress_conn_log_file": "/var/log/drlink/egress/connections.jsonl",
    "egress_listen_addr": "0.0.0.0",
    "egress_listen_port": 6102,
}
for obsolete in (
    "access_control_file",
    "egress_control_file",
    "service_profiles_file",
):
    if obsolete in cfg:
        cfg.pop(obsolete, None)
        changed = True
if str(cfg.get("registry_file") or "").endswith("/registry.json"):
    cfg["registry_file"] = defaults["registry_file"]
    changed = True
for key, value in defaults.items():
    if key not in cfg or cfg.get(key) in (None, ""):
        cfg[key] = value
        changed = True
if changed:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
print("CONTROL_CONFIG_OK")
PY
  fi
  # Grant drlink-egress read access to config + SQLite SSOT after inode replace.
  local eg_mod=""
  if [[ -n "${BASE_DIR:-}" && -f "$BASE_DIR/lib/frp_egress_control.py" ]]; then
    eg_mod="$BASE_DIR/lib/frp_egress_control.py"
  else
    eg_mod="$(frp_server_fs /usr/local/lib/drlink/frp_egress_control.py)"
  fi
  if [[ -f "$eg_mod" ]]; then
    python3 - "$eg_mod" "$cfg_file" "$db_file" <<'PY' || true
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("frp_egress_control", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cfg = Path(sys.argv[2])
db = Path(sys.argv[3])
mod.reapply_egress_runtime_permissions(
    config_path=cfg if cfg.is_file() else None,
    control_db_path=db if db.is_file() else None,
    parents=True,
)
print("CONTROL_PERMS_OK")
PY
  fi
  if [[ "$created" == "1" ]]; then
    echo "CONTROL_PLANE_BOOTSTRAP=created"
  else
    echo "CONTROL_PLANE_BOOTSTRAP=existing"
  fi
  return 0
}

frp_server_apply_project_upgrade() {
  local source="$1" check_only="${2:-0}"
  local version_file previous target staged snapshot backups preserved_before
  local restart_frps=0 restart_alloc=0 restart_access=0 restart_egress=0 restart_tcp_egress=0 restart_frontend=0 restart_mcp=0 rel
  local resolved_channel resolved_ref
  local candidate_meta target_channel target_ref
  local installed_channel installed_ref installed_bundle target_bundle
  local update_needed=1 vcmp

  _FRP_UPGRADE_MUTATION_STARTED=0
  _FRP_UPGRADE_ROLLBACK_DONE=0
  _FRP_UPGRADE_ROLLBACK_RC=0
  _FRP_UPGRADE_IN_ROLLBACK=0

  # Server project-update owns the server transaction marker only.
  FRP_TXN_ROLE=server
  export FRP_TXN_ROLE

  [[ -d "$source" ]] || { echo "ERROR: update source directory is required" >&2; return 1; }
  # Local git checkouts persist exact HEAD as SOURCE_REF (pretags-safe Zero-Touch).
  frp_infer_expected_source_ref_from_git_source "$source"
  frp_infer_expected_source_from_release_manifest "$source"
  if [[ ${EUID} -ne 0 && -z "${FRP_SERVER_TEST_ROOT:-}" ]]; then
    echo "ERROR: run with sudo" >&2
    return 1
  fi
  # Upgrade from pre-rename installs must migrate paths before presence checks.
  frp_migrate_legacy_product_paths || return 1
  [[ -f "$(frp_server_fs /etc/drlink/config.json)" ]] &&
  [[ -s "$(frp_server_fs /etc/frp/server_token)" ]] &&
  [[ -f "$(frp_server_fs /var/lib/drlink/registry.json)" ]] &&
  [[ -f "$(frp_server_fs /etc/drlink/pki/ca.crt)" ]] || {
    echo "ERROR: no complete existing Data Relay Link server installation was found" >&2
    return 1
  }

  frp_load_installed_server_runtime || return 1
  if ! frp_resolve_project_update_identity; then
    return 1
  fi
  resolved_channel="$FRP_RESOLVED_RELEASE_CHANNEL"
  resolved_ref="$FRP_RESOLVED_SOURCE_REF"

  candidate_meta="$(frp_server_upgrade_validate_source_metadata \
    "$source" "${FRP_EXPECTED_SOURCE_REF:-}" "$resolved_channel")" || return 1
  target="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $1}')"
  target_channel="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $2}')"
  target_ref="$(printf '%s' "$candidate_meta" | awk -F'\t' '{print $3}')"
  version_file="$(frp_server_fs /etc/drlink/version)"
  previous="$(frp_read_kv_file "$version_file" PROJECT_VERSION)"
  previous="${previous:-legacy / unknown}"
  installed_channel="$(frp_server_display_or_unknown "${FRP_INSTALLED_RELEASE_CHANNEL:-}")"
  installed_ref="$(frp_server_display_or_unknown "${FRP_INSTALLED_SOURCE_REF:-}")"
  installed_bundle="$(frp_server_display_or_unknown "${FRP_INSTALLED_BUNDLE_SHA256:-}")"
  if [[ "$previous" != "legacy / unknown" ]]; then
    vcmp="$(frp_version_compare "$previous" "$target")"
    if [[ "$vcmp" == "gt" ]]; then
      target_bundle="$(frp_server_verified_bundle_sha256 || true)"
      frp_server_report_identity "$previous" "$target" \
        "$installed_channel" "$target_channel" \
        "$installed_ref" "$target_ref" \
        "$installed_bundle" "$(frp_server_display_or_unknown "$target_bundle")"
      echo "FRP binary update         : NO"
      echo "ERROR: installed project version ${previous} is newer than candidate ${target}" >&2
      frp_emit_failure_class DOWNGRADE_REFUSED
      return 1
    fi
  fi

  staged="$(frp_secure_mktemp_dir)"
  trap 'rm -rf "'"$staged"'"' RETURN
  frp_server_upgrade_stage "$source" "$staged" || return 1
  if ! frp_server_upgrade_validate_staged "$staged"; then
    echo "ERROR: staged update failed validation; installed files were not changed." >&2
    echo "UPGRADE_ROLLBACK=NOT_REQUIRED"
    return 1
  fi
  target_bundle="$(frp_server_target_build_identity "$staged")"
  frp_server_report_identity "$previous" "$target" \
    "$installed_channel" "$target_channel" \
    "$installed_ref" "$target_ref" \
    "$installed_bundle" "$target_bundle"
  echo "FRP binary update         : NO"

  if [[ "$previous" != "legacy / unknown" ]]; then
    vcmp="$(frp_version_compare "$previous" "$target")"
    if [[ "$vcmp" == "eq" ]]; then
      if [[ "$installed_bundle" =~ ^[0-9a-fA-F]{64}$ ]] && \
         [[ "$(printf '%s' "$installed_bundle" | tr '[:upper:]' '[:lower:]')" == "$target_bundle" ]]; then
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
    echo "State mutation             : NO"
    return 0
  fi

  if [[ "$update_needed" == "0" ]]; then
    echo "Update                    : not needed"
    echo "State mutation             : NO"
    return 0
  fi

  # Before mutation: refuse if Egress listen is owned by a published service.
  if ! frp_server_upgrade_precheck_egress_port; then
    echo "State mutation             : NO"
    frp_emit_failure_class EGRESS_PORT_COLLISION
    return 1
  fi

  # Before mutation: adopt legacy shared marker into the server path when
  # unambiguous. Never inspect or clear the client marker.
  frp_txn_adopt_legacy_marker server || return 1

  frp_acquire_server_lock || return 1
  trap 'frp_release_server_lock; rm -rf "'"$staged"'"' RETURN
  preserved_before="$(frp_server_upgrade_preserved_digest)"
  backups="$(frp_server_fs /var/lib/drlink/backups)"
  snapshot="${backups}/project-update-$(date -u +%Y%m%dT%H%M%SZ)"
  FRP_INSTALL_SNAPSHOT="$snapshot"
  frp_server_create_snapshot "$snapshot" || return 1
  frp_prune_backup_dirs "$backups" "$FRP_SERVER_UPGRADE_BACKUP_KEEP"

  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-server.service && restart_frps=1
  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-allocator.service && restart_alloc=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp-port-allocator.py && restart_alloc=1
  # Any Python module imported by the allocator must be listed in FRP_ALLOCATOR_RUNTIME_HELPERS.
  for rel in "${FRP_ALLOCATOR_RUNTIME_HELPERS[@]}"; do
    frp_server_upgrade_changed "$staged" "usr/local/lib/drlink/${rel}" && restart_alloc=1
  done
  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-access.service && restart_access=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp-access-plugin.py && restart_access=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp_access_control.py && restart_access=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_runtime_policy.py && restart_access=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_db.py && restart_access=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_plane.py && restart_access=1
  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-egress.service && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp-egress-gateway.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp_egress_control.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp_egress_control.py && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-tcp-egress.service && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink-tcp-egress.py && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp_egress_runtime.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/frp_egress_runtime.py && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_runtime_policy.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_db.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_plane.py && restart_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_runtime_policy.py && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_db.py && restart_tcp_egress=1
  frp_server_upgrade_changed "$staged" usr/local/lib/drlink/drlink_control_plane.py && restart_tcp_egress=1
  if frp_server_upgrade_is_single443; then
    frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-frontend.service && restart_frontend=1
  fi
  frp_server_upgrade_changed "$staged" etc/systemd/system/drlink-mcp-bridge.service && restart_mcp=1
  for rel in "${FRP_MCP_BRIDGE_RUNTIME_HELPERS[@]}"; do
    frp_server_upgrade_changed "$staged" "usr/local/lib/drlink/${rel}" && restart_mcp=1
  done

  if [[ "$-" == *E* ]]; then
    _FRP_UPGRADE_ERRTRACE_WAS=1
  else
    _FRP_UPGRADE_ERRTRACE_WAS=0
    set -E
  fi
  trap '_frp_server_upgrade_err; frp_release_server_lock; rm -rf "'"$staged"'"; if [[ "${_FRP_UPGRADE_ERRTRACE_WAS}" != "1" ]]; then set +E; fi; exit 1' ERR
  trap 'if [[ "${_FRP_UPGRADE_ERRTRACE_WAS}" != "1" ]]; then set +E; fi; trap - ERR; frp_release_server_lock; rm -rf "'"$staged"'"' RETURN

  FRP_TXN_RELEASE_CHANNEL="$target_channel" \
  FRP_TXN_SOURCE_REF="$target_ref" \
  FRP_TXN_BUNDLE_SHA256="${target_bundle:-}" \
  FRP_TXN_SNAPSHOT_PATH="$snapshot" \
  FRP_TXN_MUTATION_STARTED=true \
    frp_txn_write project-update commit "$previous" "$target"
  _FRP_UPGRADE_MUTATION_STARTED=1

  if ! frp_server_upgrade_install_staged "$staged"; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  if ! frp_install_qualified_artifacts_from "$source"; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  # Project file install must not mutate protected runtime state.
  if [[ "$(frp_server_upgrade_preserved_digest)" != "$preserved_before" ]]; then
    echo "ERROR: protected server state changed during project file install" >&2
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class STATE_PRESERVATION_FAILED
    return 1
  fi
  if ! frp_server_upgrade_ensure_egress; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  restart_egress=1
  # SQLite control-plane bootstrap for upgrades from pre-SQLite installs.
  # Must run before access/egress restarts so /healthz authority=sqlite succeeds.
  local control_bootstrap_out=""
  if ! control_bootstrap_out="$(frp_server_upgrade_ensure_control_plane)"; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  printf '%s\n' "$control_bootstrap_out"
  if printf '%s\n' "$control_bootstrap_out" | grep -q 'CONTROL_PLANE_BOOTSTRAP=created'; then
    restart_access=1
    restart_egress=1
    restart_tcp_egress=1
  fi
  # Controlled Egress / control-plane bootstrap may intentionally add keys to
  # config.json and create protected state (egress-control.json / drlink.db).
  # Re-baseline after those deliberate migration steps.
  preserved_before="$(frp_server_upgrade_preserved_digest)"
  if ! frp_server_upgrade_post_mutation_guard; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  if [[ "${FRP_SERVER_UPGRADE_HOOK_FAIL:-}" == "verify" ]]; then
    echo "ERROR: simulated post-install verification failure" >&2
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class HEALTH_CHECK_FAILED
    return 1
  fi
  if [[ "$(frp_server_upgrade_preserved_digest)" != "$preserved_before" ]]; then
    echo "ERROR: protected server state changed during project update" >&2
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class STATE_PRESERVATION_FAILED
    return 1
  fi
  # Generated frontend is not a staged project file. Rebuild it from the
  # installed generator and runtime inputs, then activate only if it validates.
  if ! frp_server_upgrade_converge_frontend; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  if frp_server_unit_runtime_stale drlink-mcp-bridge \
      "$(frp_server_fs /usr/local/lib/drlink/drlink_mcp_bridge.py)"; then
    restart_mcp=1
  fi

  if [[ "$restart_frps" == "1" || "$restart_alloc" == "1" || "$restart_access" == "1" || "$restart_egress" == "1" || "$restart_tcp_egress" == "1" || "$restart_frontend" == "1" || "$restart_mcp" == "1" ]]; then
    if ! frp_server_skip_systemd; then
      frp_server_systemctl daemon-reload || {
        frp_server_upgrade_rollback "$snapshot"; return 1;
      }
    else
      frp_server_record_action "daemon-reload"
    fi
  fi
  if [[ "$restart_access" == "1" ]]; then
    frp_server_restart_unit drlink-access || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_access || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_egress" == "1" ]]; then
    frp_server_restart_unit drlink-egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_tcp_egress" == "1" ]]; then
    frp_server_restart_unit drlink-tcp-egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    # Prefer install-server health helper when available (same tree / sourced upgrade).
    if declare -F frp_server_health_tcp_egress >/dev/null 2>&1; then
      frp_server_health_tcp_egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    elif ! frp_server_skip_systemd; then
      frp_wait_unit_active drlink-tcp-egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    fi
  fi
  if [[ "$restart_frps" == "1" ]]; then
    frp_server_restart_unit drlink-server || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_frps || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_alloc" == "1" ]]; then
    frp_server_restart_unit drlink-allocator || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_allocator "$(frp_server_upgrade_allocator_port)" ||
      { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_mcp" == "1" ]]; then
    frp_server_restart_unit drlink-mcp-bridge || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_mcp_bridge || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_frontend" == "1" ]]; then
    frp_server_restart_unit drlink-frontend || { frp_server_upgrade_rollback "$snapshot"; return 1; }
    frp_server_health_frontend || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_frps" != "1" ]]; then
    frp_server_health_frps || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_alloc" != "1" ]]; then
    frp_server_health_allocator "$(frp_server_upgrade_allocator_port)" ||
      { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_access" != "1" ]]; then
    frp_server_health_access || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "$restart_egress" != "1" ]]; then
    frp_server_health_egress || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if frp_server_upgrade_is_single443 && [[ "$restart_frontend" != "1" ]]; then
    frp_server_health_frontend || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ -f "$(frp_server_fs /etc/systemd/system/drlink-mcp-bridge.service)" && "$restart_mcp" != "1" ]]; then
    frp_server_health_mcp_bridge || { frp_server_upgrade_rollback "$snapshot"; return 1; }
  fi
  if [[ "${FRP_SERVER_UPGRADE_HOOK_FAIL:-}" == "runtime-converged" ]]; then
    echo "ERROR: simulated runtime convergence failure" >&2
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class HEALTH_CHECK_FAILED
    return 1
  fi

  if ! FRP_RELEASE_CHANNEL="$target_channel" \
      FRP_EXPECTED_SOURCE_REF="$target_ref" \
      FRP_EXPECTED_SOURCE_HEAD="${FRP_EXPECTED_SOURCE_HEAD:-}" \
      FRP_BUNDLE_SHA256="$target_bundle" \
      FRP_VERSION_REQUIRE_VERIFIED_BUNDLE=1 \
      PROJECT_VERSION="$target" \
      frp_write_version_file "$version_file" server; then
    frp_server_upgrade_rollback "$snapshot"
    frp_emit_failure_class FILE_COMMIT_FAILED
    return 1
  fi
  _FRP_UPGRADE_MUTATION_STARTED=0
  frp_txn_clear server
  FRP_INSTALL_SNAPSHOT=""
  frp_migrate_legacy_systemd_units || true
  frp_audit_emit project_update.completed
  echo "Server project update completed successfully."
  echo "Project version : ${previous} -> ${target}"
  echo "Release channel : ${target_channel}"
  echo "Source ref      : ${target_ref}"
  echo "Bundle SHA256   : ${target_bundle}"
  if [[ "$previous" == "$target" ]]; then
    echo "Same-version update : refreshed management files"
  fi
  echo "FRP binary      : unchanged"
  echo "Server state    : preserved"
  echo "Client re-enroll: NOT REQUIRED"
}
