# Proposal

## Why

The accepted Data Relay Link v2.4 contract is currently distributed across large living documents, implementation commits, and E2E evidence. Several older documents also retain superseded or stale models, so an AI agent can read a plausible but obsolete statement and silently treat it as current truth.

This bootstrap creates a structured OpenSpec baseline for the highest-value accepted decisions without changing product behavior.

## What Changes

- Establish `openspec/specs/` as the structured canonical contract for accepted v2.4 behavior.
- Backfill six high-value capabilities from the current v2.4 FINAL Master and Product Master.
- Preserve decision rationale and supersession history separately from current requirements.
- Define Server versus Agent Host configuration boundaries explicitly.
- Require future behavior changes to enter through an OpenSpec change rather than silent master-document edits.
- Keep implementation and E2E as qualification evidence; do not infer undocumented rationale from code.
- **No runtime behavior, CLI behavior, API behavior, or release behavior is changed by this bootstrap.**

Authoritative bootstrap sources are `docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`, `docs/PRODUCT_MASTER.md`, `docs/SECURITY.md`, `docs/CONFIGURATION_BUNDLE.md`, and `docs/CLI_REFERENCE.md` at local baseline HEAD `bb333c4f7c8584ba4c6fbd8a792c2a452adb78ab`. Source code and tests are used only as implementation/evidence cross-checks.

## Capabilities

### New Capabilities

- `product-model`: Canonical public concepts, Server/Agent Host contexts, and superseded intermediate vocabulary.
- `remote-service`: Agent-local Remote Service lifecycle, destination/service validation, DEGRADED semantics, and endpoint stability.
- `fixed-tcp`: Fixed TCP as a Service Object subtype with its own endpoint pool and Remote Service integration.
- `access-policy`: Canonical Remote/Internet/AI Access policy-mode semantics and separation between policy and connectivity.
- `configuration-bundle`: Declarative change-set behavior, context-local atomicity, idempotency, and Server/Agent scope.
- `management-security`: Enrolled Agent management identity and authenticated Agent-to-Server management operations.

### Modified Capabilities

None. This is the first structured OpenSpec baseline.

## Impact

This change adds OpenSpec/Cursor workflow files and structured specifications only. Existing implementation remains untouched. The large master documents remain migration/reference inputs during transition, but once a capability is represented in OpenSpec, future changes to that behavior must update the OpenSpec capability through a reviewed change.

Explicit non-goals: rewriting all documentation, reconstructing undocumented historical rationale, changing runtime code, claiming unproven qualification status, or importing every legacy behavior into the initial baseline.
