#!/usr/bin/env bash
# Operator entry that runs PASS1 and then PASS2 on the current HEAD.
# The release contract invokes tests/run-release-qualification-pass.sh once
# per full_e2e_passes instead of calling this wrapper inside that loop.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -f "$ROOT/e2e-reports/release-qualification/state.env"
bash "$ROOT/tests/run-release-qualification-pass.sh"
bash "$ROOT/tests/run-release-qualification-pass.sh"
