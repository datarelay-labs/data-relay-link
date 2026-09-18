# Tasks

## 1. Definition of Done

- [x] 1.1 Add the repository Definition of Done with automatic and evidence-based completion criteria.
- [x] 1.2 Add deterministic governance verification and focused tests.
- [x] 1.3 Update AI operating rules so agents use the same DoD and never infer PASS.

## 2. Security gates

- [x] 2.1 Add GitHub Actions security gate for repository secret scanning and CodeQL Python analysis.
- [x] 2.2 Add Dependabot configuration for GitHub Actions updates.
- [x] 2.3 Enable GitHub-native secret scanning/push protection and Dependabot vulnerability/security updates when repository permissions allow.

## 3. Drift audit

- [x] 3.1 Add deterministic architecture/OpenSpec drift audit and report format.
- [x] 3.2 Add weekly/manual workflow that opens, updates, or closes a managed drift issue.

## 4. Branch protection

- [x] 4.1 Record current and target protected-branch contexts.
- [x] 4.2 Add an idempotent post-merge branch-protection configuration script.
- [x] 4.3 Do not activate new required contexts until those workflows exist on main.

## 5. Validation

- [x] 5.1 Run focused governance/security tests and strict OpenSpec validation.
- [x] 5.2 Archive this tooling change, regenerate canonical knowledge, sync Tela, commit, push, and verify the worktree is clean.
