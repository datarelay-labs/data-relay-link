#!/usr/bin/env bash
# Fail closed unless the release-gate target was chosen explicitly.
# Historical lab addresses and the frp-e2e-server alias are never implicit
# defaults. The current authorized address is not stored here.
frp_require_release_target() {
  local ip="${FRP_E2E_SERVER_IP:-}"
  local host="${FRP_E2E_PUBLIC_HOSTNAME:-}"
  local alias="${FRP_E2E_SERVER_ALIAS:-}"
  if [[ -z "$ip" || -z "$host" || -z "$alias" ]]; then
    echo "ERROR: set FRP_E2E_SERVER_IP, FRP_E2E_PUBLIC_HOSTNAME, and FRP_E2E_SERVER_ALIAS explicitly" >&2
    return 1
  fi
  case "$ip" in
    221.139.249.113|221.139.249.112)
      echo "ERROR: $ip is a historical lab address and cannot be a release-gate target" >&2
      return 1
      ;;
  esac
  case "$host" in
    *221.139.249.113*|*221.139.249.112*)
      echo "ERROR: $host is a historical lab hostname and cannot be a release-gate target" >&2
      return 1
      ;;
  esac
  if [[ "$alias" == "frp-e2e-server" ]]; then
    echo "ERROR: frp-e2e-server is the historical lab alias and cannot be a release-gate target" >&2
    return 1
  fi
  return 0
}
