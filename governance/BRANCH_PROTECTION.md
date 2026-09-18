# Main Branch Protection Policy

## Current required contexts

The repository currently protects `main` with strict required status checks for:

- lint
- distro ubuntu:22.04
- distro ubuntu:24.04
- distro rockylinux:8
- distro rockylinux:9
- distro almalinux:9
- distro amazonlinux:2023
- distro amazonlinux:2
- Windows PowerShell 5.1
- Windows PowerShell 7
- Linux pwsh cross-language
- apple-silicon
- portable

Current protection also enforces admins and blocks force-push and branch deletion.

## Target required contexts

After the governance workflows exist on `main`, add:

- openspec
- governance
- security

Keep all existing platform contexts.

Also require conversation resolution. Do not require an approving review count greater than zero while the repository is operated by a single maintainer.

## Activation rule

Never add a required context before the corresponding workflow/job exists on `main`; doing so can deadlock unrelated pull requests. `scripts/configure-main-protection.sh` checks the remote main branch before applying this policy.
