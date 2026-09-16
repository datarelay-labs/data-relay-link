# Historical — JSON Registry Schema v2 Deployment

> **Status:** Historical / superseded for the v2.4.0 target architecture
> **Do not use as the v2.4.0 deployment runbook.**

This document name is retained temporarily so historical links do not become ambiguous during the pre-stable implementation transition.

The former deployment model treated JSON registry/schema-v2 state such as:

```text
/var/lib/drlink/registry.json
```

as authoritative control-plane state.

That model is superseded by the approved v2.4.0 architecture:

```text
/var/lib/drlink/drlink.db
```

See:

```text
docs/CONTROL_PLANE_ARCHITECTURE.md
docs/PRODUCT_MASTER.md
docs/RELEASE_VALIDATION.md
```

## v2.4.0 target migration rule

The stable target has one authoritative store: embedded SQLite.

Legacy JSON may be consumed once by development/upgrade migration code where needed, but the implementation must not maintain dual authoritative writes for compatibility with unreleased development formats.

Migration sequence:

```text
consistent pre-migration backup
→ validate supported legacy input if migration is offered
→ create/migrate SQLite schema transactionally
→ foreign-key/integrity validation
→ compile runtime artifacts from SQLite
→ atomically activate
→ verify active runtime generation
→ retain legacy input only as migration backup/evidence until cleanup policy allows removal
```

An unsupported or corrupt legacy input must not cause an implicit permissive reset.

## Release requirement

Before v2.4.0 stable, canonical deployment/upgrade documentation must refer to SQLite migration/versioning rather than JSON schema v2.

This historical file may then be moved under a history/archive directory or removed when no active link depends on it; Git history remains the authoritative record of the old runbook.
