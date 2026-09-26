# Data Relay Link — v2.4.0 Release Checklist

> **Purpose:** Exact-HEAD stable qualification checklist
> **Rule:** A checked item requires retained evidence. Architecture documentation is not implementation evidence.

Authoritative classification of remaining gates is in `docs/RELEASE_VALIDATION.md`.
Do **not** tag a tree whose `PROJECT_VERSION` does not match the intended immutable tag.

FRP_VERSION=0.71.0

Published tags are immutable. Preparing the 2.4.0 immutable tag is a later qualification step. Published tags remain immutable and must never be moved, recreated, retargeted, or deleted.

## 1. Candidate identity

- [ ] `PROJECT_VERSION=2.4.0`.
- [ ] Candidate identity is an exact-SHA development build, or an optional `2.4.0-rc.N` / `preview` build. Preview/RC is not mandatory.
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
- [ ] Network Object / Network Group model implemented.
- [ ] Service Object / Service Group model implemented.
- [ ] Permission Object / Permission Group model implemented.
- [ ] Managed Host / DRLink Agent model implemented.
- [ ] Managed Host address inventory implemented.
- [ ] Agent-owned Remote Service model implemented.
- [ ] Remote Access BLACKLIST / WHITELIST policy implemented.
- [ ] Internet Access BLACKLIST / WHITELIST policy implemented.
- [ ] AI Access/MCP included and implemented.
- [ ] ConfigurationBundle included in the v2.4.0 stable target.
- [ ] direct CLI, AI-generated CLI, and ConfigurationBundle share one Change Plan/mutation engine.
- [ ] ConfigurationBundle is an idempotent change set, not a second SSOT.
- [ ] Zero-Touch ticket issuance is server-bounded to max 10/request and max 10 active unused, unique single-use tickets.

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

- [ ] Network Object CRUD for IP / CIDR / FQDN.
- [ ] Registered Managed Hosts appear as Network Objects of type Managed Host.
- [ ] Network Group CRUD and flat membership semantics.
- [ ] Service Object / Service Group CRUD.
- [ ] Permission Object / Permission Group CRUD.
- [ ] Immutable internal identity and rename/reference preservation where applicable.
- [ ] Managed Host lifecycle remains under Managed Host commands.
- [ ] Internet Access destination rejects Managed Host directly or through a Network Group.
- [ ] Context-invalid group assignment fails as a whole.
- [ ] Referenced Object/Group deletion blocked.

## 5. Endpoint inventory

- [ ] Client reports eligible local addresses.
- [ ] Active/inactive state tracked.
- [ ] Interface metadata retained where supported.
- [ ] loopback/link-local/multicast/special addresses excluded appropriately.
- [ ] Network membership uses local inventory rather than NAT/public observed source.

## 6. Remote Services

- [ ] Remote Service mutation is Agent Host-local; Server inspection is read-only for configuration.
- [ ] Each Remote Service binds one destination and one Service Object.
- [ ] TCP and Fixed TCP Service Objects are supported; UDP Remote Service is rejected.
- [ ] Another-host destination uses the current Agent Host as Relay Host.
- [ ] Endpoint identity remains stable across restart, temporary disconnect, disable/enable, and same-pool-class edit.
- [ ] Unreachable but valid targets become DEGRADED rather than being silently deleted.
- [ ] Destination/Service Object edits run policy-impact analysis.

## 7. Remote Access policy

- [ ] Initial state is No Policy / No Rules / effective ALLOW.
- [ ] BLACKLIST: matching enabled Rule DENY; no match ALLOW.
- [ ] WHITELIST: matching enabled Rule ALLOW; no match DENY.
- [ ] Rules have no ordering and no per-rule ALLOW/DENY action.
- [ ] Policy Reset removes Mode and Rules and restores initial ALLOW.
- [ ] Enforcement DISABLED preserves Mode/Rules and makes policy effective ALLOW ALL.
- [ ] Effective access also requires an enabled/reachable Remote Service.
- [ ] Policy changes apply immediately to new connections.
- [ ] Established connections are not implicitly terminated by policy edit.

## 8. Internet Access policy/security

- [ ] Same BLACKLIST / WHITELIST / Enforcement semantics proven independently from Remote Access.
- [ ] Internet Access source may use Managed Host; destination rejects Managed Host directly or through a Group containing one.
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
- [ ] Rule content/enable impact.
- [ ] Policy Mode / Enforcement impact.
- [ ] Remote Service destination/Service Object impact.
- [ ] Managed Host address membership impact.
- [ ] AI permission/target/path impact.
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
- [ ] Authentication binds a stable AI Identity.
- [ ] Anonymous privileged MCP access denied.
- [ ] Credential revoke/rotation works.
- [ ] Target = Network Object / Network Group.
- [ ] Permission = Permission Object / Permission Group.
- [ ] AI Access uses BLACKLIST / WHITELIST semantics; authentication remains mandatory.
- [ ] AI Rules have no ordering and no per-rule ALLOW/DENY action.
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

## 14.1 ConfigurationBundle / AI-assisted configuration

- [ ] `apiVersion: drlink.datarelay.run/v1alpha1` / `kind: ConfigurationBundle` schema validated.
- [ ] file input validated.
- [ ] standard-input copy/paste validated.
- [ ] no top-level `apply` root introduced; stable direct roots unchanged.
- [ ] `test configuration` is non-mutating.
- [ ] diff is generated against authoritative current state.
- [ ] identical reapply returns `NO CHANGE`.
- [ ] omission preserves resources; deletion requires explicit absent state.
- [ ] multi-resource apply is one authoritative transaction.
- [ ] reference/security validation occurs before commit.
- [ ] revision conflict aborts without partial mutation.
- [ ] broadening/destructive confirmation uses existing impact engine and defaults No.
- [ ] export is redacted and excludes tickets/secrets/private keys.
- [ ] direct CLI and equivalent bundle have semantic parity.
- [ ] AI-generated simple changes use canonical public CLI only.
- [ ] AI-generated complex changes use a copy/paste ConfigurationBundle and public `drlink` only.
- [ ] unsupported existing-client local target changes report `CLIENT_ACTION_REQUIRED`.
- [ ] bundle enrollment plans issue 0 secrets during apply.
- [ ] Zero-Touch issuance request max = 10.
- [ ] active unused Zero-Touch tickets max = 10.
- [ ] each ticket is unique/single-use and consumed atomically.
- [ ] default TTL = 1 hour; max TTL = 24 hours.
- [ ] raw ticket/install URL displayed once; server retains verifier/hash, not raw ticket.
- [ ] expired/revoked tickets release capacity without disconnecting enrolled clients.
- [ ] YAML/CLI/API cannot override server ticket ceilings.

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

- [ ] Server root = Managed Hosts / Network Objects / Service Objects / Remote Access / Internet Access / AI Access / System / Help / Exit.
- [ ] Agent Host root = Status / Remote Services / Agent / Configuration / Diagnostics / Help / Exit.
- [ ] Direct roots = show/set/unset/test/system/menu/help/exit.
- [ ] Managed Host / Network Object terminology consistent.
- [ ] Remote Service terminology consistent.
- [ ] Service Object Wizard presets are clear and are not exposed as standalone public resources.
- [ ] BLACKLIST / WHITELIST Mode and Enforcement state are visible.
- [ ] `test` explains effective policy outcome without ordered-rule semantics.
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
- [ ] no tracked commit is created after PASS2; the immutable tag is that same provenance HEAD.

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
- [ ] `DOCUMENTATION_INDEX.md` correctly classifies canonical, operator, qualification, historical, and internal documents.
- [ ] Product Master matches qualified behavior.
- [ ] Control Plane Architecture matches implementation and contains no current-behavior first-match/per-rule-ALLOW-DENY drift.
- [ ] CLI/AI Master, CLI IA, and CLI Reference match tested grammar and semantics.
- [ ] `CONFIGURATION_BUNDLE.md` matches the qualified canonical parser/schema and Server/Agent context boundaries.
- [ ] Installation and upgrade guides use immutable-source/release references appropriate to the release channel.
- [ ] Remote Access guide matches Remote Service ownership, endpoint lifecycle, and BLACKLIST/WHITELIST behavior.
- [ ] Internet Access guide matches tested security behavior.
- [ ] AI Access/MCP guide matches qualified authentication, permission, and interoperability behavior.
- [ ] Troubleshooting guide matches tested failure/recovery behavior.
- [ ] Security doc current.
- [ ] Version policy current.
- [ ] Changelog only lists qualified scope.
- [ ] ConfigurationBundle/AI copy-paste examples use canonical public CLI only.
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
NETWORK_OBJECT_MODEL=
MANAGED_HOST_MODEL=
REMOTE_SERVICE_MODEL=
REMOTE_ACCESS_POLICY=
INTERNET_ACCESS_POLICY=
AI_ACCESS_POLICY=
POLICY_IMPACT_ANALYSIS=
REVISION_AUDIT=
RUNTIME_GENERATION_CONSISTENCY=
BACKUP_RESTORE=
MCP_REAL_E2E=
CONFIGURATION_BUNDLE=
CONFIGURATION_DIRECT_CLI_PARITY=
CONFIGURATION_AI_COPY_PASTE_REAL_E2E=
ZERO_TOUCH_BOUNDED_BATCH=
FULL_REAL_E2E_PASS_1=
FULL_REAL_E2E_PASS_2=

UNRESOLVED_P0=
UNRESOLVED_P1=
UNRESOLVED_P2=
BLOCKERS=
```

`FINAL_STATUS=PASS` is invalid if any mandatory applicable gate lacks retained evidence.
