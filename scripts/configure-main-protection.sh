#!/usr/bin/env bash
set -euo pipefail

repo="${DRLINK_REPO:-datarelay-labs/data-relay-link}"
mode="${1:---dry-run}"

case "$mode" in
  --dry-run|--apply) ;;
  *)
    echo "Usage: $0 [--dry-run|--apply]" >&2
    exit 2
    ;;
esac

required_contexts=(
  "lint"
  "distro ubuntu:22.04"
  "distro ubuntu:24.04"
  "distro rockylinux:8"
  "distro rockylinux:9"
  "distro almalinux:9"
  "distro amazonlinux:2023"
  "distro amazonlinux:2"
  "Windows PowerShell 5.1"
  "Windows PowerShell 7"
  "Linux pwsh cross-language"
  "apple-silicon"
  "portable"
  "openspec"
  "governance"
  "security"
)
payload="$(mktemp)"
trap 'rm -f "$payload"' EXIT

python3 - "$payload" "${required_contexts[@]}" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
contexts = sys.argv[2:]
data = {
    "required_status_checks": {
        "strict": True,
        "contexts": contexts,
    },
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 0,
        "require_last_push_approval": False,
    },
    "restrictions": None,
    "required_linear_history": False,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "block_creations": False,
    "required_conversation_resolution": True,
    "lock_branch": False,
    "allow_fork_syncing": False,
}
out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

if [[ "$mode" == "--dry-run" ]]; then
  cat "$payload"
  echo "BRANCH_PROTECTION_MODE=DRY_RUN"
  exit 0
fi
git fetch -q origin main
for path in   .github/workflows/openspec.yml   .github/workflows/governance.yml   .github/workflows/security.yml
do
  if ! git cat-file -e "origin/main:$path" 2>/dev/null; then
    echo "BRANCH_PROTECTION_BLOCKED missing_on_main=$path" >&2
    exit 3
  fi
done

gh api   --method PUT   -H "Accept: application/vnd.github+json"   "repos/$repo/branches/main/protection"   --input "$payload" >/dev/null

echo "BRANCH_PROTECTION=APPLIED"
