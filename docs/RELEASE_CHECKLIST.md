# Data Relay Link — v2.4.0 Release Checklist

> **Purpose:** Exact-HEAD stable qualification checklist
> **Rule:** A checked item requires retained evidence. Architecture documentation is not implementation evidence.

Authoritative classification of remaining gates is in `docs/RELEASE_VALIDATION.md`.
Do **not** tag a tree whose `PROJECT_VERSION` does not match the intended immutable tag.

FRP_VERSION=0.71.0

Published tags are immutable. Preparing the 2.4.0 immutable tag is a later qualification step. Published tags remain immutable and must never be moved, recreated, retargeted, or deleted.

## 1. Candidate identity

- [ ] `PROJECT_VERSION=2.4.0`.
- [ ] Candidate identity is `2.4.0-rc.N` / `preview` before stable.
- [ ] `SOURCE_HEAD` is the exact 40-character SHA.
- [ ] Branch/worktree recorded.
- [ ] Worktree clean.
- [ ] Remote synchronized.
- [ ] Product and FRP versions recorded separately.
- [ ] Historical tags unchanged.
- [ ] `v2.4.0` does not already point elsewhere.

Evidence:

```text
RELEASE_VERSION=
RELEASE_CHANNEL=
SOURCE_HEAD=
BRANCH=
WORKTREE=
WORKTREE_CLEAN=
REMOTE_SYNCED=
UPSTREAM_ENGINE_VERSION=
CONTROL_DB_SCHEMA_VERSION=
```

## 2. Architecture scope

- [ ] `CONTROL_PLANE_ARCHITECTURE.md` matches implementation.
- [ ] SQLite is authoritative control-plane state.
- [ ] No dual authoritative JSON state remains.
- [ ] Neutral Object model implemented.
- [ ] Object Group model implemented.
- [ ] Managed Endpoint model implemented.
- [ ] Endpoint address inventory implemented.
- [ ] Published Service SELF/ROUTED implemented.
- [ ] Service Preset replaces legacy public Service Profile.
- [ ] Remote Access ordered rulebase implemented.
- [ ] Internet Access ordered rulebase implemented.
- [ ] AI Access/MCP included and implemented.

## 3. SQLite control plane

- [ ] `/var/lib/drlink/drlink.db` is authoritative.
- [ ] Foreign keys enabled.
- [ ] WAL configured.
- [ ] Synchronous durability policy configured.
- [ ] Busy timeout configured.
- [ ] Trusted schema disabled where supported.
- [ ] `schema_migrations` is authoritative migration ledger.
- [ ] Unsupported newer schema fails closed.
- [ ] Integrity/foreign-key validation implemented.
- [ ] Corruption handling is fail closed.

Evidence:

```text
CONTROL_PLANE_DB=
SQLITE_SETTINGS=
SCHEMA_MIGRATION_FRAMEWORK=
DB_CORRUPTION_FAIL_CLOSED=
```

## 4. Object model

- [ ] Host Object CRUD.
- [ ] Network Object CRUD.
- [ ] FQDN Object CRUD.
- [ ] Multiple values per static Object.
- [ ] Immutable internal Object identity.
- [ ] Rename preserves references.
- [ ] Managed Endpoint not manually creatable/deletable.
- [ ] Orphaned Managed Endpoint semantics proven.
- [ ] Object Group CRUD.
- [ ] Nested group cycle rejection where nested groups supported.
- [ ] Context-invalid group assignment fails as a whole.
- [ ] Referenced Object/Group deletion blocked.

## 5. Endpoint inventory

- [ ] Client reports eligible local addresses.
- [ ] Active/inactive state tracked.
- [ ] Interface metadata retained where supported.
- [ ] loopback/link-local/multicast/special addresses excluded appropriately.
- [ ] Network membership uses local inventory rather than NAT/public observed source.

## 6. Published Services

- [ ] SELF effective destination uses Managed Endpoint identity/address.
- [ ] Loopback local target does not break policy matching.
- [ ] ROUTED effective destination uses explicit routed target.
- [ ] ROUTED target does not require an agent on that target.
- [ ] Public port/Service identity persistence preserved.
- [ ] Target/mode edits run policy-impact analysis.

## 7. Remote Access policy

- [ ] Top-down ordering.
- [ ] First complete match wins.
- [ ] Explicit ALLOW.
- [ ] Explicit DENY.
- [ ] Implicit final DENY.
- [ ] New rule created disabled at bottom.
- [ ] before/after ordering works.
- [ ] Shadow/conflict analysis works.
- [ ] Test/explain shows ordered trace.
- [ ] Effective access also requires Published Service + reachability.
- [ ] Policy changes apply immediately to new connections.
- [ ] Established connections not implicitly terminated by policy edit.

## 8. Internet Access policy/security

- [ ] Same ordered/first-match/ALLOW/DENY/implicit-DENY semantics proven.
- [ ] Rule order independent from Remote Access.
- [ ] FQDN destinations.
- [ ] Explicit public Host/CIDR destinations where supported.
- [ ] server-side DNS.
- [ ] DNS rebinding resistance.
- [ ] validated exact-IP connect.
- [ ] SSRF/private/local/metadata protection.
- [ ] IP-literal bypass protection.
- [ ] wildcard boundary safety where supported.
- [ ] CONNECT/SNI binding where applicable.
- [ ] ECH behavior fails safely where validation depends on SNI.
- [ ] malformed proxy/TCP input fails closed.
- [ ] resource/time limits.
- [ ] Fixed TCP uses same policy authority.

## 9. Policy-impact analysis

- [ ] Object value add/remove impact.
- [ ] Object Group membership impact.
- [ ] Rule content/action/order/enable impact.
- [ ] Published Service target/mode impact.
- [ ] Endpoint-address membership impact.
- [ ] AI capability/target/path impact.
- [ ] Access broadening identified.
- [ ] Access narrowing identified.
- [ ] New/removed shadowing identified.
- [ ] Effective-action changes identified.
- [ ] Interactive broadening defaults to No.

## 10. Optimistic concurrency / transactions

- [ ] Mutable entities have row-version protection or equivalent.
- [ ] Stale wizard commit rejected.
- [ ] No lost update.
- [ ] Security mutation transaction includes revision/audit records.
- [ ] Partial mutation not reported as success.

## 11. Revision and audit

- [ ] Every control-plane mutation has revision ID.
- [ ] Actor/action/entity/result captured.
- [ ] Before/after summary bounded.
- [ ] Policy impact recorded.
- [ ] Secret/raw payload leakage prevented.
- [ ] `system audit` works.
- [ ] `system revisions` works.
- [ ] revision diff works if claimed.
- [ ] rollback only claimed if qualified and creates a new revision.

## 12. Runtime generation

- [ ] Runtime policy compiled from DB.
- [ ] Activation atomic.
- [ ] Remote policy generation records DB revision.
- [ ] Internet policy generation records DB revision.
- [ ] AI policy generation records DB revision.
- [ ] Generation mismatch surfaced.
- [ ] Unsafe mismatch fails closed.
- [ ] Status never calls a divergent plane simply Healthy.

## 13. Backup / restore / migration

- [ ] Live WAL DB backed up with SQLite Online Backup/equivalent.
- [ ] Required config/trust/secrets/provenance included.
- [ ] Naive `cp` not documented as live backup method.
- [ ] Restore validates archive and DB integrity.
- [ ] Restore validates foreign keys/schema.
- [ ] Restore preserves secure owner/mode.
- [ ] Runtime artifacts regenerated from DB.
- [ ] Runtime generation verified after restore.
- [ ] Upgrade migration has pre-upgrade backup.
- [ ] Failed migration does not leave ambiguous authority.

## 14. MCP / AI Access

- [ ] MCP Bridge runs on server.
- [ ] No per-endpoint MCP server required.
- [ ] Current official MCP spec/SDK re-verified before implementation freeze.
- [ ] Supported remote MCP transport qualified.
- [ ] Authentication binds a stable AI Principal.
- [ ] Anonymous privileged MCP access denied.
- [ ] Credential revoke/rotation works.
- [ ] Target = Managed Endpoint / Client Group.
- [ ] AI rule top-down first-match ordering.
- [ ] AI explicit ALLOW/DENY and implicit final DENY.
- [ ] AI rule before/after ordering.
- [ ] `exec` enforcement.
- [ ] `read_file` enforcement.
- [ ] `write_file` enforcement.
- [ ] `upload_file` enforcement.
- [ ] `download_file` enforcement.
- [ ] path scopes resist traversal/symlink bypass appropriate to platform.
- [ ] exec timeout/resource handling.
- [ ] true read-only policy requires `exec=false` in tests/docs.
- [ ] each new tool call evaluates current policy.
- [ ] running operation not implicitly killed by policy edit.
- [ ] AI activity audit attributable to principal/target/rule/revision.
- [ ] ChatGPT interoperability tested if claimed supported.
- [ ] Claude interoperability tested if claimed supported.
- [ ] Cursor interoperability tested if claimed supported.

Evidence:

```text
MCP_BRIDGE=
MCP_AUTH=
MCP_HOST_ROUTING=
MCP_CAPABILITY_ENFORCEMENT=
MCP_FILE_SCOPE=
MCP_AUDIT=
MCP_REAL_E2E=
```

## 15. Legacy model removal

- [ ] `registry.json` no longer authoritative.
- [ ] `egress-control.json` no longer authoritative.
- [ ] no public `service-profile` canonical resource.
- [ ] no public `internet-profile` canonical resource.
- [ ] no legacy ACL model presented as canonical.
- [ ] old v2.4 MCP exclusion removed from version/release code.
- [ ] release manifest schema no longer forces `mcp_included=false` for 2.4.x.
- [ ] release manifest generator/checkers/tests aligned to target.
- [ ] generated candidate manifest says `mcp_included=true` only when feature is actually included.

## 16. CLI UX

- [ ] Server root = Clients / Objects / Remote Access / Internet Access / AI Access / System / Help / Exit.
- [ ] Direct roots = show/set/unset/test/system/menu/help/exit.
- [ ] Object vs Client Group terminology consistent.
- [ ] Published Service terminology consistent.
- [ ] Service Preset semantics clear.
- [ ] rule order visible.
- [ ] implicit DENY visible.
- [ ] `test` explains first-match trace.
- [ ] Tab context filters invalid Object types.
- [ ] broadening confirmation visible.
- [ ] stale edit failure visible.
- [ ] backend/internal FRP helpers not leaked.
- [ ] REPL vs shell hints correct.

## 17. Version/reference integrity

- [ ] one product version SSOT.
- [ ] development/preview/stable identity correct.
- [ ] `show version` includes exact HEAD and separate FRP version.
- [ ] control DB schema/version visible.
- [ ] pre-tag bootstrap/install refs exact SHA/immutable RC.
- [ ] no future nonexistent stable-tag URL.
- [ ] no mutable fallback for qualified install.
- [ ] release manifest matches actual candidate bytes/features.

## 18. Local and CI validation

- [ ] targeted regressions pass.
- [ ] static/syntax validation pass.
- [ ] DB/migration tests pass.
- [ ] policy compiler/evaluator tests pass.
- [ ] CLI/PTY regression pass.
- [ ] lifecycle regression pass.
- [ ] security regression pass.
- [ ] MCP unit/integration pass.
- [ ] full local suite pass.
- [ ] GitHub CI pass.
- [ ] source/dist parity pass.
- [ ] secret scan pass.
- [ ] public metadata scan pass.

## 19. Real environment validation

- [ ] fresh server install.
- [ ] fresh client install.
- [ ] Zero-Touch.
- [ ] reboot/autostart.
- [ ] update/migration.
- [ ] backup/restore.
- [ ] uninstall zero-residue where purge requested.
- [ ] reinstall.
- [ ] Remote Access SSH/HTTP/HTTPS/TCP as claimed.
- [ ] ROUTED LAN target.
- [ ] Internet Access curl/wget/git/apt.
- [ ] denied Internet traffic cannot escape.
- [ ] multi-host matrix.
- [ ] MCP real operation on private/closed target.

Platform evidence:

```text
Ubuntu 24=
Rocky Linux 8=
Rocky Linux 9=
Amazon Linux 2023=
macOS Apple Silicon=
Windows 10=
```

## 20. Double Full Real E2E

- [ ] `FULL_REAL_E2E_PASS_1=PASS`
- [ ] `FULL_REAL_E2E_PASS_2=PASS`
- [ ] `PASS1_HEAD==PASS2_HEAD`
- [ ] `PASS1_HEAD==FINAL_QUALIFIED_HEAD`
- [ ] no product/dependency change between passes.
- [ ] no merge commit changed the qualified HEAD afterward.

Any change resets the pass counter.

## 21. Artifacts

- [ ] artifacts built from `FINAL_QUALIFIED_HEAD`.
- [ ] artifact SHA256 recorded.
- [ ] manifest exact source HEAD/ref/FRP version/features correct.
- [ ] `features.mcp_included=true` for final v2.4.0 candidate only after qualification.
- [ ] no secret/private lab metadata.
- [ ] final stable artifacts immutable.

## 22. Documentation

- [ ] README matches qualified behavior.
- [ ] Product Master matches qualified behavior.
- [ ] Control Plane Architecture matches implementation.
- [ ] CLI IA and CLI Reference match tested grammar.
- [ ] Internet Access guide matches tested security behavior.
- [ ] Security doc current.
- [ ] Version policy current.
- [ ] Changelog only lists qualified scope.
- [ ] known limits current.

## 23. Publication

Only after all gates:

- [ ] create immutable `v2.4.0` tag on final qualified HEAD.
- [ ] verify remote tag resolves to same HEAD.
- [ ] publish GitHub Release/artifacts/checksums/manifest.
- [ ] publish final release notes.
- [ ] atomically update stable channel.
- [ ] update public docs metadata.
- [ ] verify clean public install/bootstrap.

## 24. Final record

```text
RELEASE_VERSION=2.4.0
FINAL_QUALIFIED_HEAD=
FINAL_STATUS=PASS|PARTIAL|FAIL
RELEASE_READY=YES|NO
TAG_CREATED=YES|NO
RELEASE_PUBLISHED=YES|NO
STABLE_CHANNEL_UPDATED=YES|NO

CONTROL_PLANE_DB=
OBJECT_MODEL=
MANAGED_ENDPOINT_MODEL=
PUBLISHED_SERVICE_SELF_ROUTED=
REMOTE_ACCESS_RULEBASE=
INTERNET_ACCESS_RULEBASE=
AI_ACCESS_RULEBASE=
POLICY_IMPACT_ANALYSIS=
REVISION_AUDIT=
RUNTIME_GENERATION_CONSISTENCY=
BACKUP_RESTORE=
MCP_REAL_E2E=
FULL_REAL_E2E_PASS_1=
FULL_REAL_E2E_PASS_2=

UNRESOLVED_P0=
UNRESOLVED_P1=
UNRESOLVED_P2=
BLOCKERS=
```

`FINAL_STATUS=PASS` is invalid if any mandatory applicable gate lacks retained evidence.
