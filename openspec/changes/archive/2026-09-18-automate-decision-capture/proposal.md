# Proposal

## Why

Accepted design decisions currently become durable only when an AI explicitly edits OpenSpec by hand. Rick should not maintain proposal/design/spec files or copy context between ChatGPT, Cursor, GitHub, and the development server.

## What Changes

- Add a machine-readable Decision Event format for explicitly accepted decisions.
- Add a repository tool that validates an event and generates an OpenSpec change candidate.
- Reject exploratory, unresolved, or ambiguous decision states.
- Generate a stable Knowledge ID and preserve the original event beside the OpenSpec artifacts.
- Validate capability names and requirement operations against current OpenSpec specs.
- Run OpenSpec strict validation after generation and roll back a partial generated change on failure.
- Never auto-archive a decision; implementation and required evidence must complete first.
- Add automated tests and a GitHub Actions entry point.

## Capabilities

### New Capabilities

None. This is internal development/governance tooling and sets skip_specs: true.

### Modified Capabilities

None.

## Impact

Adds internal tooling, tests, guidance, and workflow automation. Product runtime behavior is unchanged.
