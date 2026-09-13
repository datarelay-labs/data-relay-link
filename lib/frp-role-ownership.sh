# Canonical role ownership for dual-role (server+client) uninstall.
# Sourced by uninstall-server.sh and uninstall-client.sh.
#
# Roles:
#   SERVER_ONLY — removed when uninstalling server (even if client remains)
#   CLIENT_ONLY — removed when uninstalling client (even if server remains)
#   SHARED      — removed only when the other role is NOT present
#
# Note: frp-client-common.sh is CLIENT_ONLY on client uninstall, but server
# uninstall must preserve it while a client role remains (asymmetric preserve).

# Libraries preserved by server uninstall when a client role is still present.
FRP_ROLE_SERVER_PRESERVE_IF_CLIENT=' frp-common.sh frp_mgmt_auth.py frp_health_check.py frp-client-common.sh frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_cli_catalog.py frp_ctl_repl.py frpctl drlink '

# Libraries removed by client uninstall only when server role is absent.
FRP_ROLE_CLIENT_PRESERVE_IF_SERVER=' frp-common.sh frp_mgmt_auth.py frp_health_check.py frp-doctor-common.sh frp_doctor.py frp_support_bundle.py frp_ctl_grammar.py frp_cli_catalog.py frp_ctl_repl.py frp-role-ownership.sh '

# Always removed by client uninstall.
FRP_ROLE_CLIENT_ONLY_LIB_BASENAMES=' frp-client-common.sh frp-macos.sh com.datarelay.drlink.frpc.plist '

frp_role_server_should_preserve_lib() {
  local base="$1"
  [[ "$FRP_ROLE_SERVER_PRESERVE_IF_CLIENT" == *" ${base} "* ]]
}

frp_role_client_should_preserve_lib() {
  local base="$1"
  [[ "$FRP_ROLE_CLIENT_PRESERVE_IF_SERVER" == *" ${base} "* ]]
}

frp_role_is_client_only_lib() {
  local base="$1"
  [[ "$FRP_ROLE_CLIENT_ONLY_LIB_BASENAMES" == *" ${base} "* ]]
}

# Back-compat alias used by uninstall-server.sh
frp_role_is_shared_lib() {
  frp_role_server_should_preserve_lib "$1"
}
