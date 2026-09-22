#!/usr/bin/env bash
# Full local non-Docker regression suite (CI lint job equivalent, minus
# bundle rebuild and Docker distro matrix).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
# Leaked interactive/debug roots divert role-specific txn markers via frp_txn_marker_path
# precedence and produce false rollback-marker failures across the suite.
unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_EXPECTED_SOURCE_REF FRP_TXN_SOURCE_REF FRP_EXPECTED_SOURCE_HEAD \
  FRP_RELEASE_CHANNEL FRP_EXPECTED_RELEASE_CHANNEL \
  FRP_BOOTSTRAP_URL FRP_CLIENT_INSTALLER_URL FRP_WINDOWS_CLIENT_INSTALLER_URL \
  FRP_CTL_TEST_INPUT FRP_CTL_TEST_ROOT FRP_CTL_DRY_RUN FRP_CTL_ROLE \
  FRP_CTL_BIN_DIR FRP_CTL_FORCE_DRLINK || true

echo "=== MCP SDK prerequisite ==="
# Official MCP SDK is a release-blocking interop dependency (VERSION_POLICY).
# Provision a pinned, repo-local venv instead of relying on /tmp/mcp-sdk-venv.
export DRLINK_MCP_SDK_PYTHON
DRLINK_MCP_SDK_PYTHON="$(./tests/ensure-mcp-sdk-venv.sh | tail -n 1)"
echo "DRLINK_MCP_SDK_PYTHON=$DRLINK_MCP_SDK_PYTHON"

echo "=== shell syntax ==="
git ls-files '*.sh' | xargs -r bash -n
git ls-files -o --exclude-standard '*.sh' | xargs -r bash -n
bash -n tools/frp-server-status tools/frp-project-update tools/frp-update tools/frp-upstream tools/frp-client tools/frpctl

echo "=== Python compile ==="
python3 -m py_compile server/frp-port-allocator.py server/frp-access-plugin.py server/frp-egress-gateway.py server/drlink-tcp-egress.py server/migrate_token.py server/drlink-mcp-bridge.py scripts/build-bundles.py scripts/generate-sbom.py lib/frp_mgmt_auth.py lib/frp_pki.py lib/frp_frontend.py lib/frp_doctor.py lib/frp_install_txn.py lib/frp_client_registry.py lib/frp_audit.py lib/frp_project_files.py lib/frp_control_locks.py lib/frp_server_config.py lib/frp_zero_touch.py lib/drlink_qualified_artifacts.py lib/frp_ctl_grammar.py lib/frp_cli_catalog.py lib/frp_version_identity.py lib/frp_ctl_repl.py lib/frp_enrollment_lifecycle.py lib/frp_access_control.py lib/frp_egress_control.py lib/frp_egress_runtime.py lib/frp_infrastructure_ports.py lib/frp_health_check.py lib/frp_service_profiles.py lib/frp_machine_id.py lib/frp_bounded_server.py lib/frp_public_suffix.py lib/frp_policy_fingerprint.py lib/frp_state_paths.py lib/drlink_control_db.py lib/drlink_control_plane.py lib/drlink_control_cli.py lib/drlink_ai_agent.py lib/drlink_mcp_bridge.py lib/drlink_agent_payload.py
python3 -m py_compile tools/frp-create-client tools/frp-enrollments tools/frp-enrollment-revoke tools/frp-enrollment-purge tools/frp-enroll-bulk tools/frp-clients tools/frp-client-info tools/frp-client-set tools/frp-release-client tools/frp-release-service tools/frp-revoke-client tools/frp-set-client-installer-url tools/frp-server-set tools/frp-backup tools/frp-restore
python3 -m py_compile tests/test-allocator.py tests/test-enrollment-security.py tests/test-mgmt-identity.py tests/test-pki-https.py tests/test-bootstrap-ticket.py tests/test-frontend-proxy.py tests/test-client-registry.py tests/test-access-control.py tests/test-egress-control.py tests/test-service-profiles.py tests/test-destructive-selector-toctou.py tests/test-egress-create-safe-default.py tests/test-policy-fingerprint.py tests/test-strict-cli-parsing.py tests/test-cli-backend-reverse-parity.py tests/test-enabled-egress-mutation-confirm.py tests/test-lifecycle-contract-matrix.py tests/test-allocator-tls-slow-handshake.py tests/test-http-relay-half-close-idle.py tests/test-http-connection-critical-headers.py tests/test-nonce-capacity-replay.py tests/test-restore-corrupt-current.py tests/test-egress-confirm-toctou.py tests/test-state-paths-backup-restore.py tests/test-enrollment-ttl-help.py tests/test-enrollment-pair-atomicity.py tests/test-enrollment-retention-policy.py tests/test-frpctl-completion-inventory.py tests/test-cli-flag-metadata.py tests/test-operator-workflow-regressions.py tests/test-ai-access-mcp-e2e.py tests/test-mcp-public-endpoint-e2e.py tests/test-mcp-public-tls-lifecycle.py tests/test-mcp-remote-connector-interop.py tests/test-bounded-zero-touch.py tests/test-configuration-bundle.py tests/mcp_sdk_interop_client.py tests/mcp_sdk_env.py tests/test-qualified-artifacts.py tests/test-v24-ai-policy-cli-parity.py

echo "=== tests ==="
./tests/test-server-migration.sh
./tests/test-registry-init.sh
python3 tests/test-allocator.py
python3 tests/test-bootstrap-ticket.py
python3 tests/test-enrollment-security.py
python3 tests/test-enrollment-atomicity.py
python3 tests/test-enrollment-pair-atomicity.py
python3 tests/test-enrollment-retention-policy.py
python3 tests/test-mgmt-identity.py
python3 tests/test-mgmt-identity-first-gen-atomicity.py
./tests/test-client-config.sh
./tests/test-client-allocator-url.sh
./tests/test-client-platform.sh
for macos_test in ./tests/test-macos-*.sh; do
  "$macos_test"
done
./tests/test-portability.sh
./tests/test-server-install-config.sh
./tests/test-qualified-artifacts.sh
python3 tests/test-qualified-artifacts.py
./tests/test-install-config-hardening.sh
./tests/test-qual-gate-truthfulness.sh
./tests/test-public-hostname.sh
./tests/test-allocator-ready.sh
./tests/test-create-client.sh
./tests/test-zero-touch-bootstrap.sh
./tests/test-pending-enroll-recovery.sh
./tests/test-ssh-explicit-user.sh
./tests/test-passive-online.sh
./tests/test-io-hardening.sh
./tests/test-pending-enrollments.sh
./tests/test-show-enrollments.sh
./tests/test-enrollment-retention.sh
python3 tests/test-core-correctness-p1.py
./tests/test-core-correctness-lifecycle.sh
./tests/test-cli-hardening.sh
./tests/test-cli-catalog-parity.sh
python3 tests/test-no-legacy-current-surface.py
python3 tests/test-canonical-runtime-policy.py
./tests/test-release-blockers-cli.sh
./tests/test-enroll-bulk.sh
./tests/test-zero-service-client.sh
./tests/test-management-commands.sh
./tests/test-client-metadata.sh
./tests/test-client-tags.sh
./tests/test-client-groups.sh
python3 tests/test-client-registry.py
python3 tests/test-control-state-concurrency.py
python3 tests/test-control-state-global-lock.py
python3 tests/test-restore-preflight.py
python3 tests/test-restore-readiness.py
./tests/test-frp-client.sh
./tests/test-release-service-client-state-reconcile.sh
./tests/test-client-sync-reconcile.sh
./tests/test-source-arg.sh
./tests/test-lifecycle.sh
./tests/test-guided-ux.sh
./tests/test-verb-first-cli-ux.sh
./tests/test-cli-information-architecture.sh
python3 tests/test-ai-access-mcp-e2e.py
python3 tests/test-mcp-public-endpoint-e2e.py
python3 tests/test-mcp-public-tls-lifecycle.py
python3 tests/test-mcp-remote-connector-interop.py
python3 tests/test-public-cli-grammar-parity.py
python3 tests/test-public-cli-runtime-matrix.py
python3 tests/test-lifecycle-cli-ux.py
python3 tests/test-operational-ux-cli-recovery-closure.py
python3 tests/test-release-recovery-dual-role-audit-docs-closure.py
python3 tests/test-repl-live-inventory.py
./tests/test-real-e2e-canonical-cli.sh
./tests/test-client-upgrade.sh
./tests/test-safe-repo-copy.sh
bash ./tests/test-installed-client-update.sh
./tests/test-legacy-client-secure-bridge.sh
./tests/test-install-lifecycle.sh
./tests/test-partial-client-install-recovery.sh
./tests/test-uninstall-owned-frpc.sh
./tests/test-uninstall-stdin-execution.sh
./tests/test-uninstall-zero-residue.sh
./tests/test-frpctl.sh
./tests/test-frpctl-suggest-portable.sh
./tests/test-frpctl-completion.sh
./tests/test-frpctl-pty-completion.sh
./tests/test-frpctl-pty-prompt-backspace.sh
./tests/test-frpctl-pty-create-confirm.sh
./tests/test-installer-dns-prompt-pty.sh
./tests/test-frp-compat-gate.sh
./tests/test-create-zero-touch.sh
python3 tests/test-bounded-zero-touch.py
python3 tests/test-configuration-bundle.py
./tests/test-zero-touch-short-command.sh
./tests/test-zero-touch-short-url.sh
python3 tests/test-zero-touch-windows-pin.py
./tests/test-product-upgrade-policy.sh
./tests/test-frpctl-doctor.sh
./tests/test-port-architecture.sh
./tests/test-egress-port-architecture.sh
./tests/test-perf-baseline-evidence-contract.sh
./tests/test-harness-gate-truthfulness.sh
python3 tests/test-access-control.py
./tests/test-access-control.sh
python3 tests/test-egress-control.py
python3 tests/test-fixed-tcp-egress.py
./tests/test-fixed-tcp-egress.sh
python3 tests/test-tcp-egress-admission-ordering.py
python3 tests/test-bounded-server-slot-release.py
python3 tests/test-egress-conn-log-traverse-only.py
python3 tests/test-egress-conn-log-rotation.py
python3 tests/test-egress-conn-log-rotation-concurrency.py
python3 tests/test-egress-shared-parent-permissions.py
python3 tests/test-egress-create-safe-default.py
python3 tests/test-enabled-egress-mutation-confirm.py
python3 tests/test-operator-workflow-regressions.py
python3 tests/test-egress-confirm-toctou.py
python3 tests/test-destructive-selector-toctou.py
python3 tests/test-http-relay-half-close-idle.py
python3 tests/test-http-connection-critical-headers.py
python3 tests/test-nonce-capacity-replay.py
python3 tests/test-restore-corrupt-current.py
python3 tests/test-state-paths-backup-restore.py
python3 tests/test-enrollment-ttl-help.py
python3 tests/test-frpctl-completion-inventory.py
python3 tests/test-cli-flag-metadata.py
python3 tests/test-lifecycle-contract-matrix.py
python3 tests/test-allocator-tls-slow-handshake.py
python3 tests/test-policy-fingerprint.py
python3 tests/test-strict-cli-parsing.py
python3 tests/test-cli-backend-reverse-parity.py
python3 tests/test-egress-runtime-permissions.py
./tests/test-egress-control.sh
./tests/test-client-stop-fail-closed.sh
python3 tests/test-machine-id-validation.py
./tests/test-authoritative-state-missing.sh
./tests/test-target-health.sh
./tests/test-support-bundle.sh
python3 tests/test-service-profiles.py
./tests/test-service-profiles.sh
./tests/test-user-facing-branding.sh
./tests/test-legacy-identity-migration.sh
./tests/test-legacy-frpc-unit-migration.sh
./tests/test-client-proxy-health-wait.sh
./tests/test-ca-bootstrap.sh
./tests/test-allocator-process-cleanup.sh
./tests/test-pki-https.py
python3 tests/test-frontend-proxy.py
./tests/test-distro-matrix.sh
./tests/test-frp-update.sh
./tests/test-server-project-update.sh
./tests/test-project-file-manifest.sh
./tests/test-real-bundle-project-update.sh
./tests/test-frp-server-status.sh
./tests/test-release-docs.sh
./tests/test-release-artifact-ordering.sh
./tests/test-probe-tcp-injection.sh
./tests/test-immutable-release-channel.sh
./tests/test-exact-sha-installer-provenance.sh
./tests/test-version-governance.sh
python3 tests/test-release-manifest-schema.py
./scripts/check-release-governance.sh
./tests/test-install-txn-rollback.sh
./tests/test-fresh-install-sandbox-rollback.sh
python3 tests/test-audit-log.py
./tests/test-frp-compatibility.sh
./tests/test-backup-restore.sh
./tests/test-server-uninstall-fail-closed.sh
python3 tests/test-release-partial-acl.py
python3 tests/test-v24-upgrade-reconcile.py
python3 tests/test-v24-status-parity.py
python3 tests/test-v24-managed-host-policy.py
python3 tests/test-v24-runtime-allocator.py
python3 tests/test-v24-mgmt-api-auth.py
python3 tests/test-v24-cli-ai-master.py
python3 tests/test-v24-cli-ai-master-closure.py
python3 tests/test-v24-false-pass-hardening.py
python3 tests/test-v24-final-closure.py
python3 tests/test-v24-doc-consistency.py
python3 tests/test-v24-ai-policy-cli-parity.py
python3 tests/test-v24-manual-e2e-findings.py
python3 tests/test-v24-cli-workflow-semantic-parity.py
python3 tests/test-v24-ai-access-reference-integrity.py
python3 tests/test-v24-ai-path-scope-public-parity.py
python3 tests/test-v24-group-policy-test-false-assurance.py
python3 tests/test-v24-service-policy-consistency.py
python3 tests/test-v24-access-broadening-bundle-order.py
python3 tests/test-v24-managed-host-retirement.py
python3 tests/test-v24-user-lifecycle-ux.py
python3 tests/test-v24-ai-auth-convergence.py
python3 tests/test-v24-ai-job-safety.py
python3 tests/test-v24-ai-jobs-json1-independence.py
python3 tests/test-v24-authoritative-connectivity-convergence.py
python3 tests/test-v24-internet-runtime-parity.py
python3 tests/test-v24-managed-host-reference-safety.py
python3 tests/test-v24-network-mutation-atomicity.py
python3 tests/test-v24-oneshot-strict-partial-edit.py
python3 tests/test-v24-real-managed-host-executor.py
python3 tests/test-v24-remote-service-distributed-atomicity.py
python3 tests/test-v24-restore-atomic-cutover.py
python3 tests/test-v24-unified-disaster-recovery.py
python3 tests/test-v24-upgrade-policy-preservation.py
python3 tests/test-v24-whitelist-last-rule-outage-safety.py
python3 tests/test-human-ux-framework-unit.py
./tests/test-agent-runtime-payload.sh
./tests/test-orphan-suite-coverage.sh

echo "=== leftover test allocators ==="
# shellcheck source=lib/frp-test-procs.sh
. "$ROOT/tests/lib/frp-test-procs.sh"
if ! frp_test_assert_no_tmp_allocators; then
  echo "FAIL leftover test-owned allocators after run-all" >&2
  frp_test_stop_tmp_allocators || true
  exit 1
fi
echo "POST_RUN_ALL_TEST_ALLOCATORS=0"

echo "=== secret scan ==="
./scripts/secret-scan.sh

echo "=== public metadata scan ==="
./scripts/check-public-metadata.sh

echo "=== whitespace ==="
git diff --check HEAD

echo
echo "RUN_ALL=PASS"
echo "Note: Docker matrix is ./tests/run-distro-matrix.sh"
echo "Note: bundle parity is ./scripts/build-bundles.sh && git diff --exit-code dist/"
echo "Note: SHA256SUMS is ./scripts/verify-sha256sums.sh"
echo "Note: full artifact chain is ./scripts/build-release-artifacts.sh"
