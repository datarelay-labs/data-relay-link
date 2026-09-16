# Changelog

All notable released changes to Data Relay Link are recorded here.

Released tags/artifacts are immutable. Historical source is never rewritten to make version numbering or current architecture look cleaner.

## [Unreleased]

### Candidate target: 2.4.0

v2.4.0 remains a development target. The following is approved architecture scope, not a stable-release claim. Final notes must be reconciled against the exact qualified HEAD before publication.

### Added — target scope

- Embedded SQLite control plane at `/var/lib/drlink/drlink.db` with migration, revision, audit, and runtime-generation metadata.
- Neutral reusable Objects and Object Groups.
- Managed Endpoint policy identity and endpoint local-address inventory.
- Published Service target modes: SELF and ROUTED.
- Ordered Remote Access rulebase with explicit ALLOW/DENY, top-down first-match, implicit default DENY, shadow detection, and policy-impact analysis.
- Ordered Internet Access rulebase using the same Object model while retaining controlled-egress DNS/SSRF/rebinding protections.
- Optimistic-concurrency protection for interactive control-plane mutations.
- Consistent SQLite backup/restore and DB-to-runtime recompilation.
- AI Principal and AI Access policy model.
- Server-side MCP Bridge reusing Data Relay Link Managed Endpoints instead of deploying an MCP server per internal host.
- AI capability/path/exec authorization and AI operation audit.

### Changed — target scope

- Control-plane authority moves from multiple authoritative JSON state files to embedded SQLite.
- Public `Service Profile` is replaced by `Service Preset`, a creation-time convenience with no ownership of existing services.
- Legacy `Internet Profile` policy is replaced by the ordered Internet Access rulebase.
- Legacy ACL/Access Rule-centric inbound policy is replaced by the ordered Remote Access rulebase.
- Ambiguous generic Group terminology is split into Client Group and Object Group.
- Inbound relay resources are described as Published Services.
- Canonical guided CLI root becomes Clients / Objects / Remote Access / Internet Access / AI Access / System.
- Earlier v2.4.x MCP exclusion decision is superseded: MCP/AI Access is now part of the v2.4.0 target and must be qualified before stable release.

### Security — target scope

- Explicit ALLOW and DENY with implicit default DENY.
- Object/Group/Published Service mutations participate in policy-impact analysis.
- Access broadening requires explicit interactive confirmation.
- Referenced policy entities are protected from cascade delete.
- Unsupported/corrupt DB or unsafe runtime-generation mismatch fails closed where safe enforcement cannot be proven.
- Internet Access retains server-side DNS, DNS-rebinding resistance, SSRF/special-address protection, and validated exact-destination connection.
- MCP operations require authenticated AI Principal identity and per-invocation policy authorization.
- True read-only AI policy requires `exec=false`.

### Removed from target public model

- Authoritative `registry.json` control-plane model.
- Authoritative `egress-control.json` control-plane model.
- Canonical public `service-profile` resource.
- Canonical public `internet-profile` resource.
- Canonical ACL-only inbound model.
- v2.4.x MCP-exclusion release rule.

### Before release

- Implement all approved architecture on one exact candidate HEAD.
- Remove/replace old MCP-exclusion code, tests, schema constraints, and release scripts.
- Generate a candidate manifest that reflects actual included features.
- Complete automated validation, multi-host Real E2E, MCP interoperability qualification, backup/restore/migration, and security regressions.
- Pass Full Real E2E twice on the same exact final HEAD.
- Create the immutable `v2.4.0` tag only afterward.

## Historical releases

Historical tags remain the authority for released/historical content. Current repository history includes immutable tags through `v2.3.0`; do not reconstruct old release notes from memory or move old tags.

## Entry template

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
### Changed
### Deprecated
### Fixed
### Security
### Removed
### Known limits
### Provenance
- Source HEAD: `<40-character SHA>`
- Relay Engine: `<version>`
- Control DB Schema: `<version>`
- Manifest: `<release-manifest artifact>`
```
