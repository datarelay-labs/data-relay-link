# Proposal

## Why

Data Relay Link already has strong multi-platform CI and real E2E discipline, but completion criteria, security gates, architecture drift detection, and the intended protected-branch policy are not yet expressed as one automated governance layer. AI-generated changes need deterministic rules so that "PASS" means the same thing every time.

## What Changes

- Add a machine-verifiable Definition of Done and AI operating rule.
- Add a lightweight governance gate that validates OpenSpec, canonical knowledge freshness, decision automation, repository security invariants, and governance configuration.
- Add GitHub security workflows for secret scanning and CodeQL Python analysis.
- Add Dependabot updates for GitHub Actions.
- Add a scheduled architecture/spec drift audit that opens or updates a GitHub issue when drift is detected and closes it when the repository returns to a clean baseline.
- Define the intended main branch protection checks and provide an idempotent configuration script for post-merge activation.
- Enable GitHub-native secret scanning/push protection and Dependabot vulnerability/security updates where repository permissions allow.

## Capabilities

### New Capabilities

None. This is repository governance and uses skip_specs: true.

### Modified Capabilities

None.

## Impact

No product runtime behavior changes. Changes are limited to CI, security, governance automation, documentation, and agent operating rules.
