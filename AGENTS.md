# Data Relay Link Engineering Rules

This repository adopts the canonical Solo AI Engineering System.

Canonical engineering system:
- repository: https://github.com/datarelay-labs/engineering-system
- version: 1.2.1
- baseline commit: 540d00edd438f6656fb865902bd295126265bd4f

## Minimum context first

Always:
1. Read this `AGENTS.md`.
2. Read `.engineering/project.yaml`.

Only when relevant:
3. For implementation/debugging/testing, read `.engineering/tests.yaml`.
4. For release/version/artifact work, read `.engineering/release.yaml`.
5. Read only the relevant product specification/ADR/runbook/Engineering System standard.

Do not preload all standards, Wiki pages, archived specifications, or historical discussion.

## Data Relay Link execution rules

1. Identify affected domains, public contracts, persisted state, security boundaries, operational impact, and required tests.
2. Make the smallest correct change.
3. Run affected deterministic tests first.
4. Ordinary PRs use affected tests plus the fast PR guardrail; they do not run `./tests/run-all.sh` by default.
5. Full deterministic/lifecycle/platform/performance/operational E2E qualification belongs at the exact release-candidate boundary.
6. A known blocking deterministic regression stops expensive downstream qualification.
7. Do not duplicate equivalent native and shared CI evidence.
8. Bug fixes require durable regression coverage whenever practical.
9. Never weaken a valid test merely to obtain PASS.
10. Never claim release readiness from historical evidence or a different source HEAD.

Data Relay Link release qualification remains exact-HEAD and operational-E2E driven.
