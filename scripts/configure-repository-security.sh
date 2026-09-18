#!/usr/bin/env bash
set -euo pipefail

repo="${DRLINK_REPO:-datarelay-labs/data-relay-link}"
mode="${1:---dry-run}"

case "$mode" in
  --dry-run)
    cat <<'EOF'
REPOSITORY_SECURITY_TARGET
secret_scanning=enabled
secret_scanning_push_protection=enabled
dependabot_security_updates=enabled
vulnerability_alerts=enabled
automated_security_fixes=enabled
EOF
    echo "REPOSITORY_SECURITY_MODE=DRY_RUN"
    exit 0
    ;;
  --apply) ;;
  *)
    echo "Usage: $0 [--dry-run|--apply]" >&2
    exit 2
    ;;
esac

gh api --method PATCH "repos/$repo" --input - >/dev/null <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"},
    "dependabot_security_updates": {"status": "enabled"}
  }
}
JSON

gh api --method PUT "repos/$repo/vulnerability-alerts" >/dev/null
gh api --method PUT "repos/$repo/automated-security-fixes" >/dev/null || true

echo "REPOSITORY_SECURITY=APPLIED"
