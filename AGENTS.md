# Data Relay Link Engineering Rules

This repository adopts the Data Relay Labs Solo AI Engineering System.

Canonical engineering system:
- repository: https://github.com/datarelay-labs/engineering-system
- baseline commit: 0f97b4c1e30ea6bf588b24b9890a48b7aee01adf

Before modifying code:

1. Read `.engineering/project.yaml`.
2. Read `.engineering/tests.yaml`.
3. Read `.engineering/release.yaml` for release-related work.
4. Identify affected domains and public contracts.
5. Inspect existing implementation and tests before changing behavior.
6. Make the smallest correct change and avoid unrelated refactors.
7. Run the most relevant deterministic tests first, then wider gates based on risk.
8. Bug fixes require a durable regression test whenever practical.
9. Never weaken a valid test merely to obtain PASS.
10. Do not claim release readiness from historical evidence or a different source HEAD.

Data Relay Link release qualification remains exact-HEAD and operational-E2E driven.
