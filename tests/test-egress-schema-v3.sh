#!/usr/bin/env bash
# Schema v3 migration-focused checks (subset of test-fixed-tcp-egress.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/tests/test-fixed-tcp-egress.sh"
