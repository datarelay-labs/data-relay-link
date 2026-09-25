#!/usr/bin/env bash
# Fail closed unless the release-gate target was chosen explicitly and the
# alias, public hostname, and IP identify that same host.
# Historical lab addresses and the frp-e2e-server alias are never implicit
# defaults. The current authorized address is not stored here.
frp_release_target_name_ips() {
  local name="$1"
  if [[ "$name" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    printf '%s\n' "$name"
    return 0
  fi
  getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u
}

frp_release_target_ips_are() {
  local want="$1"
  local got="$2"
  local line seen=0
  [[ -n "$got" ]] || return 1
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" == "$want" ]] || return 1
    seen=1
  done <<<"$got"
  [[ "$seen" -eq 1 ]]
}

frp_release_target_alias_hostname() {
  local alias="$1"
  ssh -G "$alias" 2>/dev/null | awk '$1 == "hostname" { print $2; exit }'
}

frp_require_release_target() {
  local ip="${FRP_E2E_SERVER_IP:-}"
  local host="${FRP_E2E_PUBLIC_HOSTNAME:-}"
  local alias="${FRP_E2E_SERVER_ALIAS:-}"
  local host_ips alias_host alias_ips
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
  host_ips="$(frp_release_target_name_ips "$host" || true)"
  if ! frp_release_target_ips_are "$ip" "$host_ips"; then
    echo "ERROR: FRP_E2E_PUBLIC_HOSTNAME $host does not identify FRP_E2E_SERVER_IP $ip" >&2
    return 1
  fi
  alias_host="$(frp_release_target_alias_hostname "$alias" || true)"
  if [[ -z "$alias_host" ]]; then
    echo "ERROR: FRP_E2E_SERVER_ALIAS $alias does not identify FRP_E2E_SERVER_IP $ip" >&2
    return 1
  fi
  alias_ips="$(frp_release_target_name_ips "$alias_host" || true)"
  if ! frp_release_target_ips_are "$ip" "$alias_ips"; then
    echo "ERROR: FRP_E2E_SERVER_ALIAS $alias does not identify FRP_E2E_SERVER_IP $ip" >&2
    return 1
  fi
  return 0
}
