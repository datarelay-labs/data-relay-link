#!/usr/bin/env bash
# Human UX Adversarial E2E — deterministic operator-emulation suite.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1
# Never inherit live lab / interactive roots into the isolated harness.
unset FRP_UPDATE_ROOT FRP_DEPLOY_TEST_ROOT FRP_SERVER_TEST_ROOT \
  FRP_CLIENT_TEST_ROOT FRP_UNINSTALL_TEST_ROOT FRP_ROLE_TEST_ROOT \
  FRP_CTL_TEST_INPUT FRP_CTL_TEST_ROOT DRLINK_MGMT_URL DRLINK_MGMT_TOKEN || true

exec python3 tests/human-ux-e2e/runner.py "$@"
