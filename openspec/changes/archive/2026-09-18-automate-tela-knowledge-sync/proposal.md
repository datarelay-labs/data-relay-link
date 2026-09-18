# Proposal

## Why

OpenSpec is now the canonical contract and decision history, while Tela is the searchable knowledge layer used by ChatGPT and Cursor. Today the canonical Tela page is manually curated, so it can drift from OpenSpec or require Rick to maintain documentation.

## What Changes

- Generate a deterministic canonical knowledge document from current OpenSpec specs and accepted product decision archives.
- Store Tela project/space/page identifiers as non-secret repository configuration.
- Require connected AI agents to update the canonical Tela page after a qualified OpenSpec archive.
- Keep Atlas-generated pages secondary to OpenSpec-derived canonical knowledge.
- Verify the Tela update with a read-back and a decision-history search.
- Do not store Tela OAuth tokens, PATs, or secrets in Git.

## Capabilities

### New Capabilities

None. This is governance/knowledge automation and sets skip_specs: true.

### Modified Capabilities

None.

## Impact

Adds derived knowledge generation, agent operating rules, tests, and Tela synchronization metadata. Product runtime behavior is unchanged.
