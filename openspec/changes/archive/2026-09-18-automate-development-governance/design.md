# Design

## Context

The repository already requires lint, Linux distro, Windows, and macOS checks on main. OpenSpec/Tela automation exists on the governance branch but is not yet a required main-branch check. GitHub-native secret scanning and Dependabot security updates are currently disabled.

## Decisions

### Decision: Definition of Done has automatic and evidence-based layers

Deterministic repository checks are enforced by CI. Environment-dependent Real E2E remains PASS or N/A-with-rationale evidence; AI agents must not claim PASS without evidence.

### Decision: Governance gate stays lightweight

The existing lint job already runs the full non-Docker suite. Governance CI must not duplicate that expensive suite. It validates OpenSpec, decision/knowledge automation, security invariants, and policy structure only.

### Decision: Drift audit is scheduled and non-destructive

The weekly audit reports contract/document drift through one managed GitHub issue. It never rewrites product specs or code automatically.

### Decision: Security uses defense in depth

Keep the repository's deterministic secret-scan script, add CodeQL for Python, enable GitHub secret scanning and push protection when possible, and use Dependabot for GitHub Actions dependencies.

### Decision: Branch protection activation waits until checks exist on main

The target policy is versioned now, but new required contexts are not added to main until the workflows have landed on main. This avoids deadlocking unrelated open PRs with checks that cannot run from their base.

## Failure semantics

- Governance/security failure blocks merge once the checks are required.
- Drift audit failure opens/updates an issue but does not mutate OpenSpec.
- Missing Real E2E evidence is reported as NOT_PROVEN, never inferred as PASS.
