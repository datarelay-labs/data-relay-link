# Tasks

## 1. Canonical projection

- [x] 1.1 Add Tela sync configuration containing only non-secret project/space/page identifiers.
- [x] 1.2 Implement a deterministic OpenSpec-to-knowledge renderer and generate the canonical knowledge artifact.
- [x] 1.3 Add tests for current requirements, accepted decisions, skip_specs filtering, and deterministic check mode.

## 2. Agent automation

- [x] 2.1 Update AGENTS.md and Cursor rules with mandatory post-archive Tela synchronization.
- [x] 2.2 Update OpenSpec archive guidance so knowledge regeneration/sync is part of closure.
- [x] 2.3 Document failure semantics: OpenSpec remains authoritative and Tela failure becomes KNOWLEDGE_SYNC_PENDING.

## 3. Live validation

- [x] 3.1 Update Tela page 4312 from the generated artifact through MCP.
- [x] 3.2 Read back the page and verify Fixed TCP decision rationale is retrievable.
- [x] 3.3 Run OpenSpec/tests, archive this tooling change, commit, push, and verify clean status.
