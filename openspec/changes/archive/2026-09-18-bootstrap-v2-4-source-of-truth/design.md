# Design

## Context

See proposal.md for motivation. The v2.4 closure worktree contains a final CLI/AI Master, Product Master, domain documents, implementation, and extensive tests, but these sources have different roles and freshness. Some older documents still describe a superseded intermediate public model.

The bootstrap baseline is taken from local HEAD `bb333c4f7c8584ba4c6fbd8a792c2a452adb78ab`, which is 27 commits ahead of the then-current GitHub feature-branch HEAD. The worktree was clean before OpenSpec initialization.

## Goals / Non-Goals

**Goals:**
- Make accepted behavior machine-discoverable as small capability specs.
- Preserve why major v2.4 decisions were made or what they superseded.
- Prevent code, stale docs, or AI inference from silently redefining accepted behavior.
- Establish a workflow that future ChatGPT/Cursor changes can update automatically.

**Non-Goals:**
- Rewriting every existing document now.
- Treating implementation presence as proof of qualification.
- Reconstructing rationale that was never documented.
- Changing product behavior during bootstrap.

## Decisions

### Decision: OpenSpec becomes the structured contract layer
Current capability specs under `openspec/specs/` are the canonical structured contract after bootstrap archive. Large master documents remain reference/migration sources until progressively converted.

**Rationale:** Smaller capability contracts reduce stale-document ambiguity and allow a behavior change to carry proposal, rationale, delta, tasks, and archive history together.

**Alternative considered:** Keep PRODUCT_MASTER/CLI Master as the only authority. Rejected because the documents already mix current contract, historical decisions, implementation notes, and qualification state.

### Decision: Backfill accepted contract, not inferred implementation
The baseline copies only behavior explicitly accepted by the current FINAL Master/Product Master and supporting canonical documents. Source and tests are cross-check evidence only.

**Rationale:** Code can lag design, contain compatibility paths, or encode a bug. Inferring design rationale from code would corrupt decision history.

**Alternative considered:** Generate specs automatically from source/tests. Rejected as an authority model; it remains useful only as drift/evidence analysis.

### Decision: Start with six high-value capabilities
The initial baseline covers product model, Remote Service, Fixed TCP, Access Policy, ConfigurationBundle, and management security.

**Rationale:** These areas contain the highest concentration of recent design decisions and superseded terminology. Incremental migration avoids turning bootstrap into another monolithic rewrite.

**Alternative considered:** Convert the entire repository in one pass. Rejected because it would increase noise and make unresolved or stale statements harder to distinguish from accepted contract.

### Decision: Preserve supersession rather than rewriting history
The v2.4 final public model explicitly supersedes the intermediate Managed Endpoint / Published Service / Service Preset / ordered first-match ALLOW-DENY / AI Principal model.

**Rationale:** The FINAL Master optimizes for a smaller operator mental model and common semantics across human CLI, AI one-shot, and ConfigurationBundle.

**Consequence:** Legacy/internal terminology may remain in code during migration, but it cannot override the current public contract.

### Decision: Fixed TCP remains a Service Object subtype
Fixed TCP is modeled as a Service Object subtype. External endpoint allocation happens only when a Remote Service uses it, from a separate Fixed TCP pool.

**Rationale:** This keeps policy/service selection in one object model while preserving endpoint-pool integrity and hiding allocator-managed listen ports from normal operator configuration.

**Rejected alternative:** A separate Fixed TCP policy/object hierarchy.

### Decision: ConfigurationBundle atomicity is context-local
Server and Agent Host Bundles are independently atomic; one atomic Bundle never spans both contexts.

**Rationale:** Server and Agent own different authoritative state and can be temporarily disconnected. Distributed transaction semantics would make simple configuration depend on cross-host availability.

**Rejected alternative:** One distributed atomic Bundle across Server plus one or more Agents.

### Decision: Reachability is not configuration validity
A valid Agent-local Remote Service may be saved as DEGRADED when a destination or Server is temporarily unreachable, provided required references can be resolved locally.

**Rationale:** Configuration lifecycle and runtime reachability are separate. Temporary failure must not force endpoint churn or reject valid desired state.

**Rejected alternative:** Fail Remote Service create/edit solely because the target or Server is currently unreachable.

### Decision: Agent management uses enrolled identity
Agent-to-Server management and synchronization use the enrolled Agent management identity while canonical CLI hides signing details.

**Rationale:** Management mutations require authenticated machine identity without adding credential mechanics to normal operator workflows.

## Risks / Trade-offs

- **[Risk] Existing derived docs can still drift from OpenSpec.** → Add CI drift checks and progressively generate/synchronize derived docs.
- **[Risk] Bootstrap may omit lower-priority accepted behavior.** → Add capabilities incrementally when touched; omission is not permission to redefine behavior.
- **[Risk] Old implementation nouns can confuse AI agents.** → Project context explicitly defines authority and superseded vocabulary.
- **[Risk] Qualification status can be overstated.** → Keep E2E evidence separate from normative requirements and require explicit evidence before claiming qualification.

## Migration Plan

1. Initialize OpenSpec and Cursor workflows on a branch based on the latest clean v2.4 local HEAD.
2. Create and validate the six bootstrap delta specs plus this decision history.
3. Archive the bootstrap change with spec synchronization so the six capabilities become current specs.
4. Add lightweight CI validation for OpenSpec structure and future deltas.
5. Use OpenSpec change workflow for new product-behavior decisions.
6. Later add Knowledge Bridge / LLM Wiki ingestion from archived changes and evidence.

Rollback is simple during bootstrap: delete the OpenSpec/Cursor additions or revert the bootstrap commit; runtime product behavior is unaffected.
