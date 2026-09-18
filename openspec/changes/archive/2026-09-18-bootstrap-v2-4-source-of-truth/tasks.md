# Tasks

## 1. OpenSpec bootstrap

- [x] 1.1 Initialize OpenSpec for Cursor on the clean v2.4 closure worktree and verify `openspec doctor --json` reports a healthy root.
- [x] 1.2 Add project authority/context rules in `openspec/config.yaml` and verify OpenSpec context resolves the repository root.
- [x] 1.3 Backfill six accepted v2.4 capability deltas and verify every proposal capability has a corresponding spec file.
- [x] 1.4 Record migration and supersession decisions in `design.md` and verify undocumented rationale is not inferred from implementation.

## 2. Validation and source-of-truth activation

- [x] 2.1 Run strict OpenSpec validation for the bootstrap change and fix all structural/spec errors until validation passes.
- [x] 2.2 Archive the bootstrap change with spec synchronization and verify the six current specs exist under `openspec/specs/`.
- [x] 2.3 Re-run `openspec doctor` and strict validation after archive and verify there are no active bootstrap deltas left.

## 3. Automation guardrails

- [x] 3.1 Add GitHub CI pinned to OpenSpec 1.13.1 and validate its YAML plus the local strict-validation command.
- [x] 3.2 Store source-of-truth authority rules in OpenSpec project context so Cursor/OpenSpec workflows receive them automatically.
- [x] 3.3 Verify the bootstrap branch changes only OpenSpec/Cursor/CI governance files and does not modify product runtime code.

## Follow-up

Knowledge Bridge / LLM Wiki ingestion is intentionally a separate future OpenSpec change after this baseline is integrated.
