# Changelog

All notable released changes to Data Relay Link are recorded here.

Released tags/artifacts are immutable. Historical source is never rewritten to make version numbering or current architecture look cleaner.

## [Unreleased]

### Implemented (feature branch)

- ConfigurationBundle Change Plan engine (`lib/drlink_configuration_bundle.py`) with public CLI:
  `system export configuration`, `test configuration`, `system diff configuration`,
  `system apply configuration` (file or stdin).
- Shared mutation path: Bundle apply uses ControlPlane batch mode + one revision/audit/compile cycle.
- Bounded Zero-Touch issuance enforced in `issue_bootstrap_ticket` / batch API:
  max 10 per issue, max 10 active unused, default TTL 1h, max TTL 24h, verifier-only persistence,
  batch revoke by `batch_id`. Bundle enrollment plans issue zero tickets.

## 2.4.0 — development target

### Candidate target: 2.4.0

v2.4.0 remains a development target. The following is approved architecture scope, not a stable-release claim. Final notes must be reconciled against the exact qualified HEAD before publication.

### Added — target scope

- Embedded SQLite control plane at `/var/lib/drlink/drlink.db` with migration, revision, audit, and runtime-generation metadata.
- Managed Host / DRLink Agent identity with Managed Hosts selectable as Network Objects where policy context allows it.
- Network Objects / Groups for IP, CIDR, FQDN, and Managed Host selectors.
- Service Objects / Groups, including Fixed TCP as a Service Object subtype.
- Permission Objects / Groups for reusable AI-operation permissions.
- Agent-owned Remote Services binding one destination and one Service Object, with TCP and Fixed TCP support and stable endpoint allocation.
- Remote Access, Internet Access, and AI Access using the shared BLACKLIST / WHITELIST Mode and Enforcement model.
- AI Identity authentication plus server-side MCP Bridge and per-invocation AI Access authorization.
- Optimistic-concurrency protection for interactive control-plane mutations.
- Consistent SQLite backup/restore and DB-to-runtime recompilation.
- ConfigurationBundle v1alpha1 for idempotent multi-resource change sets using the same Change Plan/control-plane engine as direct CLI.
- AI-assisted configuration contract: simple changes as canonical public CLI; dependent changes as copy/paste ConfigurationBundle via standard input.
- Redacted configuration export plus validate/test/diff/atomic-apply workflow.
- Zero-Touch bounded issuance: max 10 tickets per request, max 10 active unused, unique single-use tickets, default 1-hour TTL and maximum 24-hour TTL.

### Changed — target scope

- Control-plane authority is transferred from multiple authoritative JSON state files to embedded SQLite.
- Public terminology is frozen around Managed Host, Network/Service/Permission Objects and Groups, AI Identity, Remote Service, Remote Access, Internet Access, and AI Access.
- Initial policy state is No Policy / No Rules with effective ALLOW; BLACKLIST denies matching enabled Rules and WHITELIST allows matching enabled Rules.
- Rules are not ordered and do not carry per-rule ALLOW/DENY actions; Policy Reset and Enforcement disable/enable have explicit semantics.
- Remote Service mutation is Agent Host-local; Server-side Remote Service inspection is read-only for configuration.
- Internet Access source selectors may include Managed Hosts; destinations reject Managed Hosts directly or through a Network Group containing one.
- Fixed TCP endpoint allocation uses a separate implementation-managed port pool and does not create a separate policy hierarchy.
- Canonical guided Server CLI root becomes Managed Hosts / Network Objects / Service Objects / Remote Access / Internet Access / AI Access / System / Help / Exit.
- Canonical Agent Host CLI root becomes Status / Remote Services / Agent / Configuration / Diagnostics / Help / Exit.
- Earlier v2.4.x MCP exclusion decision is superseded: MCP/AI Access is part of the v2.4.0 target and must be qualified before stable release.

### Security — target scope

- Invalid, ambiguous, corrupt, or unsafe state fails closed; policy behavior itself follows the explicit BLACKLIST / WHITELIST model.
- Managed Host, Object/Group, Remote Service, policy Mode/Enforcement, and AI permission changes participate in policy-impact analysis.
- Access broadening requires explicit interactive confirmation where the CLI contract requires it.
- Referenced policy entities are protected from cascade delete.
- Unsupported/corrupt DB or unsafe runtime-generation mismatch fails closed where safe enforcement cannot be proven.
- Internet Access retains server-side DNS, DNS-rebinding resistance, SSRF/special-address protection, and validated exact-destination connection.
- MCP operations require authenticated AI Identity and per-invocation AI Access authorization; authentication remains mandatory even when AI Access enforcement is disabled.
- True read-only AI policy requires `exec=false`.

### Removed from target public model

- Authoritative `registry.json` control-plane model.
- Authoritative `egress-control.json` control-plane model.
- Canonical public `service-profile` resource.
- Canonical public `internet-profile` resource.
- Intermediate public models and nouns that conflict with the frozen v2.4 Product Master / CLI-AI Master.
- Ordered first-match public rule semantics and per-rule ALLOW/DENY actions.
- v2.4.x MCP-exclusion release rule.

### Before release

- Implement all approved architecture on one exact candidate HEAD.
- Remove/replace old MCP-exclusion code, tests, schema constraints, and release scripts.
- Generate a candidate manifest that reflects actual included features.
- Complete automated validation, multi-host Real E2E, MCP interoperability qualification, backup/restore/migration, and security regressions.
- Qualify ConfigurationBundle file/stdin, idempotency, atomicity, revision conflict, direct-CLI semantic parity, AI copy/paste Real E2E, and bounded Zero-Touch ticket issuance.
- Pass Full Real E2E twice on the same exact final HEAD.
- Create the immutable `v2.4.0` tag only afterward.

## Historical releases

## 2.1.1 — hardening
## 2.1.0 — baseline

Historical tags remain the authority for released/historical content. Current repository history includes immutable tags through `v2.3.0`; do not reconstruct old release notes from memory or move old tags.

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
