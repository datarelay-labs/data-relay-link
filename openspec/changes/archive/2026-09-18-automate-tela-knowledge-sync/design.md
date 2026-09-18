# Design

## Context

ChatGPT and Cursor are both authenticated to Tela MCP. Atlas project 24 writes to space 334. The canonical page is page 4312. OpenSpec remains authoritative; Tela is a derived searchable projection.

## Decisions

### Decision: Git/OpenSpec remains canonical

The generated knowledge file is derived from current specs plus accepted product decision archives. Tela never becomes the source of truth.

### Decision: No repository-stored Tela credential

The repository stores only non-secret identifiers. ChatGPT/Cursor use their existing Tela OAuth MCP sessions to update page 4312.

### Decision: Deterministic rendering

A standard-library Python renderer extracts current requirement names and accepted Decision sections. Product archives marked skip_specs are excluded from product decision history.

### Decision: Post-archive sync is mandatory for AI agents

After a qualified product OpenSpec archive, the agent regenerates the canonical file, updates Tela page 4312, reads it back, and performs a decision-history search. Tela outage does not roll back the OpenSpec archive; it is reported as KNOWLEDGE_SYNC_PENDING and retried.

## Risks / Trade-offs

- Atlas summaries may still contain legacy terms; the canonical page explicitly outranks them.
- MCP availability depends on the connected AI client; Git remains complete even if Tela is unavailable.
