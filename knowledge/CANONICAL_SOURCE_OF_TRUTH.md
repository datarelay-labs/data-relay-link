# Data Relay Link — Canonical Source of Truth

> [!IMPORTANT]
> **Authority rule:** OpenSpec is authoritative. Tela is a derived knowledge layer.
> Atlas-generated repository summaries are secondary and may contain legacy terminology.

<!-- GENERATED FILE: do not hand-edit. -->
<!-- source_sha256: bc644b4992eabfe6bec8978bc1b4eb1e07d2ef5c8b2e48a087bd435865fa0826 -->

## How AI agents must use this knowledge

1. Prefer this page and the relevant OpenSpec current spec / archived change.
2. Treat source code and tests as implementation/evidence, not design rationale.
3. Never infer missing WHY from code; report RATIONALE_UNKNOWN when absent.
4. If Tela and OpenSpec disagree, **OpenSpec wins**.

## Current accepted contract

### access-policy

Defines the shared v2.4 Access Policy mode semantics while preserving separation between authorization and actual connectivity.

**Requirements:**
- Policy mode determines matching semantics
- Unconfigured policy allows access
- First non-interactive Rule establishes policy mode explicitly
- Policy authorization does not create connectivity

Source: openspec/specs/access-policy/spec.md

### configuration-bundle

Defines ConfigurationBundle as an idempotent declarative change set that reuses canonical DRLink validation and context-local apply semantics.

**Requirements:**
- ConfigurationBundle is not a second source of truth
- Bundle atomicity is context-local
- Bundle reapply is idempotent and deletion is explicit
- Secrets are excluded from Bundle state

Source: openspec/specs/configuration-bundle/spec.md

### fixed-tcp

Defines Fixed TCP as a Service Object subtype and its endpoint-allocation rules when used by a Remote Service.

**Requirements:**
- Fixed TCP is a Service Object subtype
- Fixed TCP endpoint allocation uses a separate pool
- Endpoint-pool class cannot change in place

Source: openspec/specs/fixed-tcp/spec.md

### management-security

Defines authentication requirements for Agent-to-Server management and synchronization operations without exposing internal signing mechanics to operators.

**Requirements:**
- Agent management operations use enrolled identity
- Operator CLI hides internal signing details
- Temporary Server disconnect does not invalidate resolvable local intent

Source: openspec/specs/management-security/spec.md

### product-model

Defines the canonical Data Relay Link v2.4 public concepts and the configuration boundaries operators and AI agents must use.

**Requirements:**
- Canonical public model
- Server and Agent Host contexts remain distinct
- Superseded public model is not authoritative

Source: openspec/specs/product-model/spec.md

### remote-service

Defines Agent-local Remote Service creation, validation, degradation, synchronization, and stable endpoint behavior for v2.4.

**Requirements:**
- Remote Service is Agent-local connectivity
- Remote Service references resolve to one target and one supported service
- Valid but unreachable configuration is retained
- Endpoint identity is stable across temporary failures

Source: openspec/specs/remote-service/spec.md

## Accepted decision history

### OpenSpec becomes the structured contract layer

Current capability specs under `openspec/specs/` are the canonical structured contract after bootstrap archive. Large master documents remain reference/migration sources until progressively converted.

**Rationale:** Smaller capability contracts reduce stale-document ambiguity and allow a behavior change to carry proposal, rationale, delta, tasks, and archive history together.

**Alternative considered:** Keep PRODUCT_MASTER/CLI Master as the only authority. Rejected because the documents already mix current contract, historical decisions, implementation notes, and qualification state.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Backfill accepted contract, not inferred implementation

The baseline copies only behavior explicitly accepted by the current FINAL Master/Product Master and supporting canonical documents. Source and tests are cross-check evidence only.

**Rationale:** Code can lag design, contain compatibility paths, or encode a bug. Inferring design rationale from code would corrupt decision history.

**Alternative considered:** Generate specs automatically from source/tests. Rejected as an authority model; it remains useful only as drift/evidence analysis.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Start with six high-value capabilities

The initial baseline covers product model, Remote Service, Fixed TCP, Access Policy, ConfigurationBundle, and management security.

**Rationale:** These areas contain the highest concentration of recent design decisions and superseded terminology. Incremental migration avoids turning bootstrap into another monolithic rewrite.

**Alternative considered:** Convert the entire repository in one pass. Rejected because it would increase noise and make unresolved or stale statements harder to distinguish from accepted contract.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Preserve supersession rather than rewriting history

The v2.4 final public model explicitly supersedes the intermediate Managed Endpoint / Published Service / Service Preset / ordered first-match ALLOW-DENY / AI Principal model.

**Rationale:** The FINAL Master optimizes for a smaller operator mental model and common semantics across human CLI, AI one-shot, and ConfigurationBundle.

**Consequence:** Legacy/internal terminology may remain in code during migration, but it cannot override the current public contract.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Fixed TCP remains a Service Object subtype

Fixed TCP is modeled as a Service Object subtype. External endpoint allocation happens only when a Remote Service uses it, from a separate Fixed TCP pool.

**Rationale:** This keeps policy/service selection in one object model while preserving endpoint-pool integrity and hiding allocator-managed listen ports from normal operator configuration.

**Rejected alternative:** A separate Fixed TCP policy/object hierarchy.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### ConfigurationBundle atomicity is context-local

Server and Agent Host Bundles are independently atomic; one atomic Bundle never spans both contexts.

**Rationale:** Server and Agent own different authoritative state and can be temporarily disconnected. Distributed transaction semantics would make simple configuration depend on cross-host availability.

**Rejected alternative:** One distributed atomic Bundle across Server plus one or more Agents.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Reachability is not configuration validity

A valid Agent-local Remote Service may be saved as DEGRADED when a destination or Server is temporarily unreachable, provided required references can be resolved locally.

**Rationale:** Configuration lifecycle and runtime reachability are separate. Temporary failure must not force endpoint churn or reject valid desired state.

**Rejected alternative:** Fail Remote Service create/edit solely because the target or Server is currently unreachable.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

### Agent management uses enrolled identity

Agent-to-Server management and synchronization use the enrolled Agent management identity while canonical CLI hides signing details.

**Rationale:** Management mutations require authenticated machine identity without adding credential mechanics to normal operator workflows.

Source: openspec/changes/archive/2026-09-18-bootstrap-v2-4-source-of-truth/design.md

## Tela sync metadata

- Atlas project: 24
- Space: 334
- Canonical page: 4312
- Source hash: bc644b4992eabfe6bec8978bc1b4eb1e07d2ef5c8b2e48a087bd435865fa0826

This file is generated from OpenSpec. Do not maintain it manually.
