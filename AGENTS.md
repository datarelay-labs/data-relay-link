# Data Relay Link Engineering Rules

This repository adopts the Data Relay Labs Solo AI Engineering System.

Canonical engineering system:
- repository: https://github.com/datarelay-labs/engineering-system
- baseline commit: f1e6294053562db2a6fa7d27797689e871c469b3

## Mandatory entry sequence

Before planning, editing, refactoring, fixing, testing, or releasing code:

1. Read this `AGENTS.md`.
2. Read `.engineering/project.yaml`.
3. Read `.engineering/tests.yaml`.
4. Read `.engineering/release.yaml` for release-related work.
5. Follow the pinned Engineering System baseline.
6. Identify affected domains and public contracts.
7. Inspect relevant existing implementation and tests.
8. Make the smallest correct change and avoid unrelated refactors.
9. Run affected deterministic tests first, then wider gates based on risk.
10. Bug fixes require durable regression coverage whenever practical.
11. Never weaken a valid test merely to obtain PASS.
12. Never claim release readiness from historical evidence or a different source HEAD.

If mandatory engineering context is missing or contradictory, stop implementation and report the configuration defect instead of guessing.

Cursor also receives the always-applied `.cursor/rules/engineering-system.mdc` rule.

Data Relay Link release qualification remains exact-HEAD and operational-E2E driven.
