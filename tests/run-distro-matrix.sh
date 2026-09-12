#!/usr/bin/env bash
# Host-side orchestrator for Docker userspace distro portability.
# Reuses tests/run-portability-container.sh inside each image.
# This is NOT real-VM, real-systemd, or SELinux validation.
set -euo pipefail

frp_matrix_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  printf '%s' "$here"
}

FRP_MATRIX_ROOT="${FRP_MATRIX_ROOT:-$(frp_matrix_root)}"
FRP_MATRIX_IMAGES_FILE="${FRP_MATRIX_IMAGES_FILE:-$FRP_MATRIX_ROOT/tests/distro-images.txt}"
FRP_MATRIX_WORKER="${FRP_MATRIX_WORKER:-$FRP_MATRIX_ROOT/tests/run-portability-container.sh}"

frp_matrix_usage() {
  cat <<'EOF'
Usage: run-distro-matrix.sh [--no-pull] [--image IMAGE]

Run systemd-free Linux userspace portability tests in Docker.

  --no-pull         Use locally cached images (do not docker pull)
  --image IMAGE     Test one supported image (default: all)

Docker CONTAINER_MATRIX=PASS does not mean REAL_VM, REAL_SYSTEMD,
SELinux Enforcing, or real ARM validation.
EOF
}

frp_matrix_load_images() {
  local line
  FRP_MATRIX_IMAGES=()
  [[ -f "$FRP_MATRIX_IMAGES_FILE" ]] || {
    echo "ERROR: missing image list: $FRP_MATRIX_IMAGES_FILE" >&2
    return 1
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] || continue
    FRP_MATRIX_IMAGES+=("$line")
  done <"$FRP_MATRIX_IMAGES_FILE"
  [[ ${#FRP_MATRIX_IMAGES[@]} -gt 0 ]] || {
    echo "ERROR: no images listed in $FRP_MATRIX_IMAGES_FILE" >&2
    return 1
  }
}

frp_matrix_supported_image() {
  local want="$1" img
  for img in "${FRP_MATRIX_IMAGES[@]}"; do
    if [[ "$img" == "$want" ]]; then
      return 0
    fi
  done
  return 1
}

frp_matrix_display_name() {
  case "$1" in
    ubuntu:22.04) printf '%s' 'Ubuntu 22.04' ;;
    ubuntu:24.04) printf '%s' 'Ubuntu 24.04' ;;
    rockylinux:8) printf '%s' 'Rocky Linux 8' ;;
    rockylinux:9) printf '%s' 'Rocky Linux 9' ;;
    almalinux:9) printf '%s' 'AlmaLinux 9' ;;
    amazonlinux:2023) printf '%s' 'Amazon Linux 2023' ;;
    amazonlinux:2) printf '%s' 'Amazon Linux 2' ;;
    *) printf '%s' "$1" ;;
  esac
}

frp_matrix_log_name() {
  printf '%s' "${1//:/-}"
}

frp_matrix_docker_cmd() {
  FRP_MATRIX_DOCKER=()
  if [[ -n "${FRP_DOCKER:-}" ]]; then
    FRP_MATRIX_DOCKER=("$FRP_DOCKER")
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is required for distro compatibility testing." >&2
    return 1
  fi
  if docker info >/dev/null 2>&1; then
    FRP_MATRIX_DOCKER=(docker)
    return 0
  fi
  if sudo -n docker info >/dev/null 2>&1; then
    FRP_MATRIX_DOCKER=(sudo -n docker)
    return 0
  fi
  echo "ERROR: Docker is installed but the daemon is not accessible." >&2
  return 1
}

frp_matrix_require_files() {
  [[ -f "$FRP_MATRIX_WORKER" ]] || {
    echo "ERROR: missing container worker: $FRP_MATRIX_WORKER" >&2
    return 1
  }
  [[ -f "$FRP_MATRIX_ROOT/lib/frp-common.sh" ]] || {
    echo "ERROR: repository files are not readable at $FRP_MATRIX_ROOT" >&2
    return 1
  }
}

frp_matrix_parse_args() {
  FRP_MATRIX_PULL=1
  FRP_MATRIX_SELECTED=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-pull)
        FRP_MATRIX_PULL=0
        shift
        ;;
      --image)
        [[ $# -ge 2 ]] || {
          echo "ERROR: --image requires an image name" >&2
          return 1
        }
        FRP_MATRIX_SELECTED+=("$2")
        shift 2
        ;;
      --image=*)
        FRP_MATRIX_SELECTED+=("${1#--image=}")
        shift
        ;;
      -h|--help)
        frp_matrix_usage
        return 2
        ;;
      *)
        echo "ERROR: unknown argument: $1" >&2
        frp_matrix_usage >&2
        return 1
        ;;
    esac
  done
}

frp_matrix_resolve_images() {
  local img
  if [[ ${#FRP_MATRIX_SELECTED[@]} -eq 0 ]]; then
    FRP_MATRIX_RUN=("${FRP_MATRIX_IMAGES[@]}")
    return 0
  fi
  FRP_MATRIX_RUN=()
  for img in "${FRP_MATRIX_SELECTED[@]}"; do
    if ! frp_matrix_supported_image "$img"; then
      echo "ERROR: unsupported image '$img'." >&2
      echo "Supported: ${FRP_MATRIX_IMAGES[*]}" >&2
      return 1
    fi
    FRP_MATRIX_RUN+=("$img")
  done
}

frp_matrix_tail() {
  local file="$1"
  if [[ -f "$file" ]]; then
    tail -n 40 "$file"
  fi
}

frp_matrix_cleanup_current() {
  if [[ -n "${FRP_MATRIX_CURRENT_NAME:-}" ]]; then
    "${FRP_MATRIX_DOCKER[@]}" rm -f "$FRP_MATRIX_CURRENT_NAME" >/dev/null 2>&1 || true
    FRP_MATRIX_CURRENT_NAME=""
  fi
}

frp_matrix_run_one() {
  local image="$1"
  local display logname logfile rc=0
  display="$(frp_matrix_display_name "$image")"
  logname="$(frp_matrix_log_name "$image")"
  logfile="${FRP_MATRIX_LOGDIR}/${logname}.log"
  FRP_MATRIX_CURRENT_NAME="frp-distro-matrix-${logname}-$$"
  echo ">>> ${display} (${image})"
  if [[ "$FRP_MATRIX_PULL" == 1 ]]; then
    if ! "${FRP_MATRIX_DOCKER[@]}" pull "$image" >>"$logfile" 2>&1; then
      echo "FAIL ${display}: docker pull failed"
      echo "log: ${logfile}"
      frp_matrix_tail "$logfile" | sed 's/^/    /'
      FRP_MATRIX_CURRENT_NAME=""
      FRP_MATRIX_RESULTS+=("${image}|FAIL|${logfile}")
      return 0
    fi
  fi
  set +e
  "${FRP_MATRIX_DOCKER[@]}" run \
    --name "$FRP_MATRIX_CURRENT_NAME" \
    --rm \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -v "${FRP_MATRIX_ROOT}:/src:ro" \
    "$image" \
    bash /src/tests/run-portability-container.sh \
    >>"$logfile" 2>&1
  rc=$?
  set -e
  FRP_MATRIX_CURRENT_NAME=""
  if [[ $rc -eq 0 ]] && grep -q '^CONTAINER_PORTABILITY=PASS$' "$logfile"; then
    echo "PASS ${display}"
    FRP_MATRIX_RESULTS+=("${image}|PASS|${logfile}")
  else
    echo "FAIL ${display}"
    echo "log: ${logfile}"
    if grep -E '^FAIL |^ERROR:' "$logfile" >/dev/null 2>&1; then
      echo "failed checks:"
      grep -E '^FAIL |^ERROR:' "$logfile" | tail -n 8 | sed 's/^/    /'
    fi
    echo "last lines:"
    frp_matrix_tail "$logfile" | sed 's/^/    /'
    FRP_MATRIX_RESULTS+=("${image}|FAIL|${logfile}")
  fi
}

frp_matrix_print_env_facts() {
  local logfile="$1"
  local key
  for key in \
    CONTAINER_DISTRO_ID \
    CONTAINER_DISTRO_NAME \
    CONTAINER_DISTRO_VERSION \
    CONTAINER_PACKAGE_MANAGER \
    CONTAINER_ARCH \
    CONTAINER_BASH \
    CONTAINER_PYTHON \
    CONTAINER_OPENSSL \
    CONTAINER_SYSTEMD_USABLE \
    CONTAINER_SYSTEMD_VERSION \
    CONTAINER_PORTABILITY \
    SYSTEMD_SMOKE \
    REAL_ARM_SYSTEMD_SMOKE
  do
    grep -E "^${key}=" "$logfile" 2>/dev/null | tail -n 1 || true
  done
}

frp_matrix_al2_notes() {
  local image="$1" result="$2" logfile="$3"
  [[ "$image" == amazonlinux:2 ]] || return 0
  echo "AMAZON_LINUX_2_CONTAINER=${result}"
  if [[ "$result" != PASS ]]; then
    echo "AMAZON_LINUX_2_OPENSSL_1_0_2_CONTAINER=${result}"
    return 0
  fi
  if grep -E '^CONTAINER_OPENSSL=.*1\.0\.2' "$logfile" >/dev/null 2>&1; then
    echo "AMAZON_LINUX_2_OPENSSL_1_0_2_CONTAINER=PASS"
  else
    echo "AMAZON_LINUX_2_OPENSSL_1_0_2_CONTAINER=FAIL"
  fi
}

frp_matrix_summary() {
  local entry image result logfile display
  local total=0 passed=0 failed=0
  local failed_list=""
  echo
  echo "============================================================"
  echo " Data Relay Link — Docker Compatibility Matrix"
  echo "============================================================"
  echo
  printf '%-20s %-20s %s\n' "Distribution" "Image" "Result"
  echo "------------------------------------------------------------"
  for entry in "${FRP_MATRIX_RESULTS[@]}"; do
    image="${entry%%|*}"
    rest="${entry#*|}"
    result="${rest%%|*}"
    logfile="${rest#*|}"
    display="$(frp_matrix_display_name "$image")"
    printf '%-20s %-20s %s\n' "$display" "$image" "$result"
    total=$((total + 1))
    if [[ "$result" == PASS ]]; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
      if [[ -n "$failed_list" ]]; then
        failed_list="${failed_list},${image}"
      else
        failed_list="$image"
      fi
    fi
  done
  echo "------------------------------------------------------------"
  echo "TOTAL=${total}"
  echo "PASSED=${passed}"
  echo "FAILED=${failed}"
  if [[ "$failed" -gt 0 ]]; then
    echo "FAILED_DISTROS=${failed_list}"
    echo "CONTAINER_MATRIX=FAIL"
  else
    echo "CONTAINER_MATRIX=PASS"
  fi
  echo
  echo "Docker CONTAINER_MATRIX does not mean REAL_VM, REAL_SYSTEMD,"
  echo "SELinux Enforcing, or real ARM validation."
  echo "SYSTEMD_SMOKE=NOT_TESTED"
  echo
  for entry in "${FRP_MATRIX_RESULTS[@]}"; do
    image="${entry%%|*}"
    rest="${entry#*|}"
    result="${rest%%|*}"
    logfile="${rest#*|}"
    if [[ "$image" == amazonlinux:2 ]]; then
      frp_matrix_al2_notes "$image" "$result" "$logfile"
    fi
  done
  echo "logs: ${FRP_MATRIX_LOGDIR}"
}

frp_matrix_main() {
  local parse_rc=0 img
  frp_matrix_load_images
  frp_matrix_parse_args "$@" || parse_rc=$?
  if [[ "$parse_rc" -eq 2 ]]; then
    return 0
  fi
  if [[ "$parse_rc" -ne 0 ]]; then
    return "$parse_rc"
  fi
  frp_matrix_resolve_images
  frp_matrix_require_files
  frp_matrix_docker_cmd

  FRP_MATRIX_LOGDIR="${FRP_MATRIX_LOGDIR:-$(mktemp -d /tmp/frp-distro-matrix.XXXXXX)}"
  mkdir -p "$FRP_MATRIX_LOGDIR"
  FRP_MATRIX_RESULTS=()
  FRP_MATRIX_CURRENT_NAME=""
  trap 'echo; echo "INTERRUPTED"; frp_matrix_cleanup_current; exit 130' INT TERM

  echo "Repository: ${FRP_MATRIX_ROOT}"
  echo "Logs:       ${FRP_MATRIX_LOGDIR}"
  echo "Images:     ${FRP_MATRIX_RUN[*]}"
  echo

  for img in "${FRP_MATRIX_RUN[@]}"; do
    frp_matrix_run_one "$img"
  done

  frp_matrix_summary
  trap - INT TERM
  for entry in "${FRP_MATRIX_RESULTS[@]}"; do
    rest="${entry#*|}"
    result="${rest%%|*}"
    if [[ "$result" != PASS ]]; then
      return 1
    fi
  done
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  frp_matrix_main "$@"
fi
