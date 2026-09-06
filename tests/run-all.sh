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
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT || true

echo "=== shell syntax ==="
git ls-files '*.sh' | xargs -r bash -n
git ls-files -o --exclude-standard '*.sh' | xargs -r bash -n
bash -n tools/frp-server-status tools/frp-project-update tools/frp-update tools/frp-upstream tools/frp-client tools/frpctl

echo "=== Python compile ==="
python3 -m py_compile server/frp-port-allocator.py server/migrate_token.py scripts/build-bundles.py lib/frp_mgmt_auth.py lib/frp_pki.py lib/frp_frontend.py lib/frp_doctor.py lib/frp_install_txn.py lib/frp_client_registry.py lib/frp_audit.py lib/frp_project_files.py lib/frp_control_locks.py lib/frp_server_config.py lib/frp_zero_touch.py lib/frp_ctl_grammar.py lib/frp_ctl_repl.py lib/frp_enrollment_lifecycle.py
python3 -m py_compile tools/frp-create-client tools/frp-enrollments tools/frp-enrollment-revoke tools/frp-enrollment-purge tools/frp-enroll-bulk tools/frp-clients tools/frp-client-info tools/frp-client-set tools/frp-release-client tools/frp-release-service tools/frp-revoke-client tools/frp-set-client-installer-url tools/frp-server-set tools/frp-backup tools/frp-restore
python3 -m py_compile tests/test-allocator.py tests/test-enrollment-security.py tests/test-mgmt-identity.py tests/test-pki-https.py tests/test-bootstrap-ticket.py tests/test-frontend-proxy.py tests/test-client-registry.py

echo "=== tests ==="
./tests/test-server-migration.sh
./tests/test-registry-init.sh
python3 tests/test-allocator.py
python3 tests/test-bootstrap-ticket.py
python3 tests/test-enrollment-security.py
python3 tests/test-mgmt-identity.py
./tests/test-client-config.sh
./tests/test-client-allocator-url.sh
./tests/test-client-platform.sh
for macos_test in ./tests/test-macos-*.sh; do
  "$macos_test"
done
./tests/test-portability.sh
./tests/test-server-install-config.sh
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
./tests/test-enroll-bulk.sh
./tests/test-zero-service-client.sh
./tests/test-management-commands.sh
./tests/test-client-metadata.sh
./tests/test-client-tags.sh
python3 tests/test-client-registry.py
python3 tests/test-restore-readiness.py
./tests/test-frp-client.sh
./tests/test-release-service-client-state-reconcile.sh
./tests/test-lifecycle.sh
./tests/test-guided-ux.sh
./tests/test-client-upgrade.sh
bash ./tests/test-installed-client-update.sh
./tests/test-legacy-client-secure-bridge.sh
./tests/test-install-lifecycle.sh
./tests/test-frpctl.sh
./tests/test-frpctl-completion.sh
./tests/test-create-zero-touch.sh
./tests/test-zero-touch-short-command.sh
./tests/test-zero-touch-short-url.sh
./tests/test-product-upgrade-policy.sh
./tests/test-frpctl-doctor.sh
./tests/test-port-architecture.sh
./tests/test-ca-bootstrap.sh
./tests/test-pki-https.py
python3 tests/test-frontend-proxy.py
./tests/test-distro-matrix.sh
./tests/test-frp-update.sh
./tests/test-server-project-update.sh
./tests/test-project-file-manifest.sh
./tests/test-real-bundle-project-update.sh
./tests/test-frp-server-status.sh
./tests/test-release-docs.sh
./tests/test-probe-tcp-injection.sh
./tests/test-immutable-release-channel.sh
./tests/test-install-txn-rollback.sh
python3 tests/test-audit-log.py
./tests/test-frp-compatibility.sh
./tests/test-backup-restore.sh

echo "=== secret scan ==="
./scripts/secret-scan.sh

echo "=== whitespace ==="
git diff --check HEAD

echo
echo "RUN_ALL=PASS"
echo "Note: Docker matrix is ./tests/run-distro-matrix.sh"
echo "Note: bundle parity is ./scripts/build-bundles.sh && git diff --exit-code dist/"
echo "Note: SHA256SUMS is ./scripts/verify-sha256sums.sh"
