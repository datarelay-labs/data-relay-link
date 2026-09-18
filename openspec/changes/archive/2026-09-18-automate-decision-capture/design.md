# Design

## Context

The repository now has six canonical OpenSpec product specs and Cursor OpenSpec workflows. The missing layer is a safe bridge from an AI conversation decision to a validated OpenSpec change candidate.

## Goals / Non-Goals

**Goals:**
- Rick only discusses and confirms; the AI produces the Decision Event and invokes the capture tool.
- Preserve WHY, rejected alternatives, affected capabilities, source references, and proposed spec deltas.
- Make generation deterministic, atomic, and machine-readable.

**Non-Goals:**
- Automatically infer acceptance from uncertain discussion text inside the repository tool.
- Automatically implement code or archive a change.
- Allow code or tests to invent undocumented rationale.

## Decisions

### Decision: Decision Event is the automation boundary
The conversational AI emits a structured JSON event after explicit acceptance. Repository automation validates that event rather than interpreting raw conversation text.

### Decision: Accepted-only gate
Only status=accepted events may generate an OpenSpec change. All other states fail closed.

### Decision: Spec deltas are explicit input
For behavior changes, the AI supplies complete normative requirement operations. The tool checks current capability and requirement names before writing.

### Decision: Generation is atomic
The tool writes a temporary change, moves it into OpenSpec, runs strict validation, and removes the generated change on validation failure.

### Decision: No automatic archive
Capture creates planning/decision artifacts only. Implementation, E2E evidence, and archive remain separate gates.

## Risks / Trade-offs

- **[Risk] Structurally valid but semantically wrong AI delta.** → Review, OpenSpec CI, implementation tests, and E2E remain required.
- **[Risk] Duplicate decisions.** → Semantic fingerprint plus stored Decision Event rejects duplicates.
- **[Risk] Workflow write permission unavailable.** → Local/connected AI path remains authoritative; GitHub workflow is an optional execution entry point.
