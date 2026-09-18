# Data Relay Link — Definition of Done

A change is **Done** only when every applicable criterion below is proven. AI agents must never convert missing evidence into PASS.

## Automatic repository gates

These are machine-verifiable and should be green before merge:

- `lint`: full non-Docker regression suite, bundle reproducibility, checksums, SBOM.
- `openspec`: OpenSpec doctor + strict validation, Decision Capture tests, Tela projection tests.
- `governance`: canonical knowledge freshness, governance invariants, architecture audit blocking checks.
- `security`: deterministic secret scan + CodeQL Python analysis.
- required Linux distribution, Windows, and macOS portability jobs.

## Evidence-based gates

These depend on the change:

- **REAL_E2E**: `PASS` when runtime/operator behavior changed and real-environment evidence exists.
- **REAL_E2E**: `N/A` only when the change cannot alter runtime/operator behavior, with rationale.
- **SECURITY_REVIEW**: `PASS` for authentication, authorization, secret, network-boundary, or privilege changes.
- **UPGRADE/ROLLBACK**: `PASS` when persistent state, installer, migration, or lifecycle behavior changed.

`NOT_TESTED`, `NOT_PROVEN`, or missing evidence is not PASS.

## Completion invariants

- Accepted behavior change has an OpenSpec change before implementation is treated as final.
- Qualified behavior is archived only after implementation and required evidence are complete.
- Current OpenSpec and generated canonical knowledge agree.
- Decision WHY and rejected alternatives are preserved when known; missing rationale is `RATIONALE_UNKNOWN`.
- No unrelated product/runtime edits are mixed into governance-only changes.
- No secrets, runtime credentials, private keys, or deployment-specific sensitive material are committed.
- Worktree is clean after commit/push.
- Required CI contexts are green before merge.

## AI operating rule

Rick should not be asked to maintain this checklist manually. ChatGPT/Cursor must evaluate it, run the available checks, preserve evidence, and report only the remaining human/environmental action when one truly cannot be automated.
