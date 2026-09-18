# Tasks

## 1. Decision Event contract

- [x] 1.1 Add a documented Decision Event schema and accepted example; verify the example passes capture validation.
- [x] 1.2 Implement deterministic Knowledge ID/change-name generation and duplicate detection; verify repeated input is rejected.

## 2. Capture implementation

- [x] 2.1 Implement the capture CLI using Python standard library only; verify accepted events generate proposal/design/spec delta/tasks.
- [x] 2.2 Reject non-accepted state, unknown capabilities, invalid requirement operations, and incomplete events; verify failures leave no generated change.
- [x] 2.3 Run strict OpenSpec validation automatically and remove generated changes if validation fails.

## 3. Automation integration

- [x] 3.1 Add focused unit/integration tests and verify the decision-capture suite passes.
- [x] 3.2 Add a GitHub Actions workflow-dispatch entry point and verify workflow YAML plus local command behavior.
- [x] 3.3 Add AI operating guidance so confirmed decisions are captured without asking Rick to maintain files manually.

## 4. Closure

- [x] 4.1 Run tooling/OpenSpec validation in an isolated worktree and verify only governance/automation files are in scope before archive.
