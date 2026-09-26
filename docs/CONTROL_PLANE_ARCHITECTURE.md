# Data Relay Link v2.4.0 — Internal Control Plane Architecture and Schema History

> **Document role:** Internal implementation/schema reference retained from the intermediate v2.4 redesign
> **Status:** Public model and policy semantics in this document are superseded by the Product Master and CLI/AI Master
> **Product:** Data Relay Link
> **Public SSOT:** `PRODUCT_MASTER.md` + `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`
> **Important:** Internal table/helper names such as `managed_endpoints`, `published_services`, `service_presets`, and `ai_principals` are storage/compatibility names only. They are not public v2.4 product nouns.

## 1. Purpose and authority

This document is retained to describe internal control-plane structure, migration history, and implementation constraints created during the v2.4 redesign. It must not redefine the frozen public model.

Current public terminology and policy behavior are defined by:

1. `PRODUCT_MASTER.md`.
2. `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`.
3. `Data Relay Link CLI Information Architecture.md`.

Actual qualified runtime behavior on an exact Git HEAD remains implementation evidence. Where the historical/intermediate terminology below conflicts with the current public SSOT, the current public SSOT wins.

Internal-name mapping used while legacy schema names remain in code:

```text
managed_endpoints  -> Managed Host Network Object projection
published_services -> Remote Service backing state
service_presets    -> Service Object wizard convenience only; not a public resource
ai_principals      -> AI Identity backing state
```

Current public nouns used for any current-behavior description in this file:

```text
Managed Host
Network Object / Network Group
Service Object / Service Group
Permission Object / Permission Group
AI Identity
Remote Service
BLACKLIST / WHITELIST Access Policy
```

Internal storage names in the mapping above are not public nouns. Superseded intermediate public nouns are listed only in section 2.

When a later section is marked historical, it is migration context. Current operator-visible behavior follows the Product Master and CLI/AI Master.

## 2. Intermediate architecture snapshot (historical)

The following values and nouns document the intermediate schema/policy design that produced much of the current internal implementation. They are retained for migration and code-reading context only. They are not current public nouns. Where these values conflict with the Product Master or CLI/AI Master, the current public SSOT wins.

| Current public noun | Superseded intermediate public noun | Internal storage / compatibility name |
| --- | --- | --- |
| Managed Host | Managed Endpoint | `managed_endpoints` |
| Remote Service | Published Service | `published_services` |
| Service Object (wizard presets) | Service Preset | `service_presets` |
| AI Identity | AI Principal | `ai_principals` |
| BLACKLIST / WHITELIST Access Policy | ordered first-match ALLOW/DENY rulebases | policy rule tables |

```text
CONTROL_PLANE_SSOT=SQLite
SQLITE_PATH=/var/lib/drlink/drlink.db
EXTERNAL_DATABASE_REQUIRED=NO

OBJECT_MODEL=NEUTRAL
SOURCE_OBJECT_TYPE=NO
DESTINATION_OBJECT_TYPE=NO

REMOTE_ACCESS_RULEBASE=ORDERED_FIRST_MATCH
INTERNET_ACCESS_RULEBASE=ORDERED_FIRST_MATCH
AI_ACCESS_RULEBASE=SEPARATE_SEMANTICS

EXPLICIT_ALLOW=YES
EXPLICIT_DENY=YES
IMPLICIT_DEFAULT_DENY=YES

POLICY_CHANGES_APPLY_TO_NEW_CONNECTIONS=YES
ESTABLISHED_CONNECTIONS_IMPLICITLY_TERMINATED=NO

MCP_INCLUDED_IN_V2_4_0_TARGET=YES
MCP_PER_ENDPOINT_SERVER_REQUIRED=NO

CONFIGURATION_BUNDLE_INCLUDED_IN_V2_4_0_TARGET=YES
CONFIGURATION_BUNDLE_SEPARATE_ENGINE=NO
CONFIGURATION_BUNDLE_SSOT=NO
CHANGE_PLAN_SHARED_BY_CLI_AND_BUNDLE=YES
ZERO_TOUCH_MAX_PER_ISSUE=10
ZERO_TOUCH_MAX_ACTIVE_UNUSED=10
ZERO_TOUCH_SINGLE_USE=YES
ZERO_TOUCH_DEFAULT_TTL=1h
ZERO_TOUCH_MAX_TTL=24h

FRP_UPSTREAM=fatedier/frp
FRP_FORK=NO
```

Canonical sentence for network policy timing:

> **Policy changes apply immediately to new connections.**

For AI operations, each new MCP tool invocation is authorized against the current policy revision. A policy edit does not implicitly kill a command that was already running.

## 3. Product planes

Data Relay Link has three access planes sharing one local control plane:

```text
                         Data Relay Link
                               │
                      SQLite Control Plane
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   Remote Access        Internet Access          AI Access
   outside → inside     inside → outside         AI → inside
          │                    │                    │
   Remote Service       proxy / fixed TCP       MCP Bridge
          │                    │                    │
   Managed Host         policy compiler         Managed Host
      or ROUTED target    / runtime artifact       / target host
```

Policy authorization and physical reachability are separate. A policy Rule match does not create a service, route, connector, or listening socket by itself.

## 4. SQLite control-plane SSOT

Authoritative state lives in:

```text
/var/lib/drlink/drlink.db
```

SQLite is embedded and local. No PostgreSQL, MySQL, Redis, or external database daemon is required.

The database owns durable identity, relationships, policy, revision metadata, and audit metadata. Runtime components do not treat generated JSON or legacy flat files as authoritative state.

Recommended SQLite settings:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA trusted_schema = OFF;
```

`PRAGMA application_id` and `user_version` may be used as defensive metadata, but the authoritative migration ledger is `schema_migrations`.

## 5. Derived runtime artifacts

Runtime consumers should receive compiled, validated artifacts rather than repeatedly interpreting mutable control-plane tables.

Conceptual layout:

```text
/var/lib/drlink/drlink.db
        │
        ▼
  Policy Compiler
        │
        ├── remote-access artifact
        ├── internet-access artifact
        └── ai-access artifact
        │
        ▼
 atomic activation / runtime reload
```

Possible path:

```text
/var/lib/drlink/runtime/
```

Artifact filenames and serialization are implementation details. The invariant is:

```text
DB = authoritative state
runtime artifact = derived state
```

A runtime generation records its source control-plane revision. A generation mismatch is a degraded/fail-closed condition, not a healthy state.

## 6. Core schema families

Tables below are the current control-plane families in `lib/drlink_control_db.py` and `lib/drlink_v24.py`. Public nouns come from the Product Master. Snake-case names are storage only.

```text
Core
  schema_migrations
  system_meta
  config_revisions
  revision_snapshots
  audit_events
  runtime_generations

Network Objects / Network Groups
  objects
  object_values
  object_groups
  object_group_members

Service Objects / Service Groups
  service_objects
  service_groups
  service_group_members

Permission Objects / Permission Groups
  permission_objects
  permission_object_members
  permission_groups
  permission_group_members

Access Policy
  access_policies          plane mode + enforcement
  policy_rules             match records; action stored as 'match'
  rule_sources
  rule_destinations
  rule_services
  rule_service_refs
  ai_policy_rules
  ai_policy_path_scopes

Managed Host projection
  clients
  managed_endpoints
  endpoint_addresses
  client_groups
  client_group_members
  client_tags

Remote Service projection
  published_services
  remote_service_meta
  agent_remote_services
  port_reservations

AI Identity
  ai_principals

Enrollment / Lifecycle
  enrollments
  enrollment_plans
```

`policy_rules.position` is an internal insertion column. It is not a public rule order. `policy_rules.action` is stored as `match` and is not a public ALLOW/DENY action. Older AI rule tables such as `ai_access_rules` remain in the schema history; current AI Access rules are `ai_policy_rules`.

`clients`, `client_groups`, and `client_group_members` are internal operational tables. They are not public policy selectors.

`service_presets` remains a storage table for wizard convenience. It is not a public resource.

Exact DDL belongs to implementation. Identity, foreign-key, revision, and fail-closed semantics in the current sections of this document follow the Product Master.

## 7. Identity model

All durable entities use immutable internal IDs. Display names are not foreign keys.

For mutable entities, include optimistic-concurrency metadata such as:

```text
id
name
row_version
created_revision
updated_revision
created_at
updated_at
```

Renaming a Network Object, Network Group, Rule, or other display entity must not break references.

Interactive workflows read the current `row_version` and must reject a commit if another writer changed that entity in the meantime.

Example failure text emitted by the current concurrency check:

```text
Object changed while you were editing it.
No changes were applied.
Review current state and retry.
```

## 7.1 Current public resources

Current public resources are defined by the Product Master. This file does not add another public model.

```text
Managed Host / DRLink Agent
Network Object / Network Group
Service Object / Service Group
Permission Object / Permission Group
AI Identity
Remote Service
Remote Access / Internet Access / AI Access
BLACKLIST / WHITELIST
```

Network Groups, Service Groups, and Permission Groups are flat. A Managed Host may be selected as a Network Object where the policy context allows it. Managed Host lifecycle stays on Managed Host commands, not `set network-object` / `unset network-object`.

Internet Access source may be IP, CIDR, FQDN, Managed Host, or a Network Group of those. Internet Access destination must not be a Managed Host, directly or through a Network Group.

Access Policy has no public rule ordering and no per-rule ALLOW/DENY action. The effective decision comes from BLACKLIST or WHITELIST mode plus enforcement.

## 8. Intermediate neutral Object model (historical)

> Sections 8–11 record the intermediate neutral Object redesign. Current public resources are in section 7.1 and the Product Master.

The intermediate model did not have separate Source Object and Destination Object resource types.

Intermediate user resources:

```text
Object
Object Group
```

The role of an Object is determined by the policy field in which it is referenced.

Example:

```text
external1
  Type: Network
  Values:
    203.0.113.0/24
    203.0.113.128/25

internal1
  Type: Network
  Values:
    10.10.10.0/24

external2
  Type: FQDN
  Values:
    google.com
    naver.com
    github.com
```

The same Object may be a Remote Access Source in one rule and an Internet Access Destination in another.

## 9. Intermediate Object types (historical)

Intermediate kinds:

```text
Host
Network
FQDN
Managed Host
Group
```

In the current schema, static Network Objects use `origin=static`. Managed Host Network Objects use `origin=managed` and are lifecycle-managed by Data Relay Link (internal table: `managed_endpoints`).

Objects may contain multiple values when those values form one logical administrative object. Operators are not forced to create one Object per IP/CIDR merely to group them immediately afterward.

## 10. Intermediate Object Group semantics (historical)

Intermediate Object Groups were reusable collections of Objects and, if implemented, nested Object Groups. Current Network Groups are flat and do not use this nested-cycle model.

Intermediate requirements:

- Immutable member references.
- Nested group cycle detection.
- No silent pruning of invalid members for a policy context.
- Assignment is fail-closed if any member makes the group invalid for the selected field.
- Referenced groups cannot be cascade-deleted.

Cycle example that must be rejected:

```text
A → B → C → A
```

## 11. Intermediate context validation (historical)

The intermediate model still restricted which Object types were legal in each field.

Intermediate context policy:

```text
Remote Access Source
  Host | Network | compatible Object Group

Remote Access Destination
  Host | Network | Managed Host | compatible Object Group

Internet Access Source
  Host | Network | compatible Object Group

Internet Access Destination
  FQDN | Host | public Network | compatible Object Group
```

That matrix is intermediate history. Current selector rules are in section 7.1 and the CLI/AI Master. Tab completion and guided selectors show only context-valid candidates for the current public model.

## 12. Managed Host

Public noun: **Managed Host**. The software on that host is the **DRLink Agent**. Storage remains `managed_endpoints` and `clients`.

A connected/enrolled DRLink Agent is represented by a Managed Host and by that host's Network Object projection.

Example:

```text
Managed Host: dp1
DRLink Agent: enrolled
Status: Connected
```

Managed Hosts appear in Network Object discovery but are not manually created with `set network-object` and are not manually deleted with `unset network-object`.

Attempting to remove one through Network Object commands must fail and direct the operator to the Managed Host lifecycle operation.

## 13. Orphaned Managed Hosts

If a Managed Host is removed while policy still references its Network Object identity, Data Relay Link must not silently reinterpret the reference or bind it to a new machine with the same label.

A referenced Managed Host identity may remain orphaned:

```text
Status: Orphaned
Reason: Client removed
```

`Client removed` is the stored `orphan_reason` value. A newly enrolled Managed Host receives its own immutable identity. Label reuse never implies identity reuse.

## 14. Endpoint address inventory

A server-observed source address can be a NAT/public address and is not sufficient to determine internal Network membership.

The DRLink Agent therefore reports an inventory of local addresses through enrollment, heartbeat, or management synchronization.

Conceptual table:

```text
endpoint_addresses
  endpoint_object_id
  address
  address_family
  interface_name
  scope
  active
  first_seen
  last_seen
```

Policy membership uses eligible active routable addresses. Loopback, link-local, multicast, and other inappropriate special addresses are excluded from internal membership calculations.

## 15. Internal client groups and public Network Group

`client_groups` and `client_group_members` are internal operational/schema history. They are not a public policy selector and they are not a public CLI resource.

The public reusable policy collection is a Network Group: a flat collection of Network Objects.

AI Access destination is a Network Object or Network Group. A Managed Host participates only through its Network Object projection where that destination context allows it.

## 16. Remote Service

Public noun: **Remote Service**. Storage remains `published_services`, with `remote_service_meta` for pool class, status, and Service Object linkage.

Inbound relay definitions are called **Remote Services** to distinguish them from Service Objects, which are protocol/port criteria.

A Remote Service records at least:

```text
id
client_id
name
service_type
target_mode
target_host
target_port
public_port
enabled
row_version
created_at
updated_at
```

Service identity and public-port reservation semantics remain stable across ordinary edits unless explicitly released.

## 17. Remote Service target modes

Canonical modes:

```text
SELF
ROUTED
```

### SELF

The effective destination is the Managed Host itself, even if the local process target is `127.0.0.1`.

Example:

```text
ssh
  Target Mode      : SELF
  Local Target     : 127.0.0.1:22
  Effective Target : dp1
  Endpoint Address : 10.10.10.10
```

Policy matching must not treat literal `127.0.0.1` as the network destination.

### ROUTED

The Managed Host acts as the connector to another reachable host/service.

Example:

```text
web1
  Target Mode      : ROUTED
  Effective Target : 10.10.10.20
  Via              : dp1
  Port             : 443
```

The routed target does not require its own DRLink Agent.

## 18. Effective Remote Access

Authorization does not expose arbitrary destinations inside a matching subnet.

Effective access is the intersection:

```text
Rule Match
+
Enabled Remote Service
+
Reachable Connector / target
=
Effective Remote Access
```

A broad destination Network Object therefore does not automatically publish every address or port in that Network Object.

## 19. Service Object wizard presets

Public v2.4 does not expose a standalone preset resource. The operator-facing Service Object wizard presets are SSH, HTTP, HTTPS, RDP, Custom TCP, and Fixed TCP. UDP is not offered in that wizard.

A preset is only a creation convenience. It pre-fills values when a Remote Service is created. It does not own the created service, does not participate in policy evaluation, and changing the preset later does not mutate existing services. The historical public names for this idea are recorded only in section 2.

## 20. Intermediate Remote Access rulebase (historical)

> Current public Remote Access uses BLACKLIST / WHITELIST semantics per the Product Master. The ordered first-match ALLOW/DENY narrative below is retained only as intermediate redesign history.

Intermediate Remote Access was an ordered rulebase.

Example:

```text
#   NAME               SOURCE       DESTINATION   SERVICE     ACTION
10  block-dp1-ssh      external1    dp1           TCP/22      DENY
20  partner-ssh        external1    internal1     TCP/22      ALLOW
30  partner-web        external1    internal1     TCP/443     ALLOW

Implicit Default                                           DENY
```

Evaluation:

1. Skip disabled rules.
2. Evaluate top to bottom.
3. Match Source.
4. Match Destination.
5. Match protocol/port criteria.
6. First complete match wins.
7. No later rule is evaluated for the decision.
8. No match means implicit DENY.

Selector composition is deterministic: multiple selectors in one dimension are OR; Source AND Destination AND Service dimensions must all match.

There is no automatic "most specific rule wins" algorithm.

## 21. Intermediate Internet Access rulebase (historical)

> Current public Internet Access uses BLACKLIST / WHITELIST semantics per the Product Master. The ordered first-match ALLOW/DENY narrative below is retained only as intermediate redesign history.

Intermediate Internet Access was a separate ordered rulebase.

Example:

```text
#   NAME              SOURCE           DESTINATION   SERVICE      ACTION
10  block-github-db   database         github        HTTPS/443    DENY
20  approved-web      internal1        external2     HTTPS/443    ALLOW

Implicit Default                                            DENY
```

Remote Access and Internet Access orderings are independent. Internet Access uses the same OR-within-dimension and AND-across-dimensions composition rule.

## 22. Internet Access destinations

Internet Access supports policy destinations represented by:

```text
FQDN
public Host IP
public CIDR
```

Unsafe local/special targets remain denied by the Internet Access security boundary, including private/local/link-local/metadata/multicast/reserved destinations where they are not explicitly part of an approved safe design.

The existing controlled-egress protections remain required: server-side DNS resolution, FQDN canonicalization, DNS rebinding resistance, validated exact-IP connection, SNI/CONNECT binding where applicable, no implicit open proxy behavior, IP-literal safety policy, and fail-closed parsing.

## 23. Current policy decision

Remote Access, Internet Access, and AI Access each have:

```text
Mode         BLACKLIST | WHITELIST
Enforcement  ENABLED | DISABLED
Rules        unordered match records
```

```text
No Policy
→ effective policy ALLOW
→ AI authentication is still mandatory

BLACKLIST
→ any enabled matching Rule DENY
→ no enabled Rule match ALLOW

WHITELIST
→ any enabled matching Rule ALLOW
→ no enabled Rule match DENY

Enforcement DISABLED
→ effective policy ALLOW ALL
→ saved Mode/Rules preserved
→ AI authentication is still mandatory
```

There is no public rule order and no per-rule ALLOW/DENY action. Deleting the last Rule preserves Mode. Policy Reset removes Mode and Rules and restores initial ALLOW.

The ordered explicit-DENY / implicit-DENY rulebase in sections 20–21 is historical only.

## 24. Rule creation

Public rule commands do not use `before` / `after` ordering. A rule is a named match of source, destination, and service or permission selectors, plus enabled state. Policy mode supplies the decision.

`policy_rules.position` may still be written as an internal insertion column. Operators do not maintain numeric sequence values, and evaluation does not use first-match order.

## 25. Overlap and impact

Overlapping match rules are valid. They are not rejected merely because more than one rule matches.

Current analysis reports security impact of a change:

```text
Access broadened
Access narrowed
Affected rules
Effective decision changes under the current mode
```

Ordered first-match explanations belong only in sections 20–21.

## 26. Policy impact analysis

Mutations to referenced entities can change effective access even when no Rule row changes.

Before committing security-relevant changes, analyze at least:

```text
Access broadened
Access narrowed
Affected active rules
Added matches
Removed matches
Effective decision changes under the current mode
```

Broadening requires explicit confirmation in interactive workflows.

Impact analysis applies to:

- Network Object values.
- Network Group, Service Group, and Permission Group membership.
- Rule source/destination/service or permission selectors and enablement.
- Access Policy mode and enforcement.
- Remote Service target or mode.
- Managed Host address inventory changes when they alter policy membership.
- AI destination, permission, and path-scope changes.

## 27. Reference protection

Referenced Network Objects, Network Groups, Service Objects, Service Groups, Permission Objects, Permission Groups, AI Identities, Managed Host identities, and other durable dependencies are not cascade-deleted.

Deletion must fail with references listed, for example:

```text
Cannot remove Network Object.
Referenced by:
  remote-access partner-ssh
  internet-access approved-web
```

The operator removes or changes references first.

## 28. Test and explain UX

Policy debugging uses actual flow inputs.

Remote Access example:

```text
test remote-access source 203.0.113.10 destination 10.10.10.50 service ssh
```

Internet Access example:

```text
test internet-access source 10.10.10.20 destination google.com service https
```

Output must show:

- Source and destination Network Object matches.
- Service or permission matches.
- Policy mode and enforcement.
- Matching enabled rules, without first-match ordering.
- Effective decision from BLACKLIST / WHITELIST semantics.
- Relevant Remote Service / reachability state for Remote Access.
- Final authorization result.

`test` is an explain/simulation operation unless the command explicitly says it performs live connectivity.

## 29. Revision model

Every material authoritative control-state mutation belongs to one committed revision. Repeated heartbeat timestamp refreshes that do not change effective state need not consume a revision; a material endpoint-address set change does because it can change policy membership and runtime generation.

Conceptual record:

```text
Revision 42
Actor   : root
Command : set network-object external2 value openai.com
```

Revision metadata should support later:

```text
system audit
system revisions
system diff
rollback
```

A revision is committed transactionally with the authoritative data change. Runtime compilation then activates a generation derived from that revision.

## 30. Audit model

Audit captures who changed what and the security impact without copying sensitive payloads blindly.

Recommended fields:

```text
timestamp
revision
actor
action
entity_type
entity_id
operation
before_summary
after_summary
impact_summary
result
```

Impact may include:

```text
access_broadened
access_narrowed
rules_affected
effective_decision_changes
```

Do not persist secrets, arbitrary full file contents, or unbounded command output into the audit database.

## 31. Transactional mutation flow

Security-relevant mutations follow one flow:

```text
read current state + row_version
→ validate request
→ resolve references
→ compute policy impact
→ interactive confirmation when required
→ BEGIN IMMEDIATE
→ re-check row_version / dependencies
→ write authoritative state
→ create revision + audit records
→ COMMIT
→ compile runtime generation
→ validate generation
→ atomically activate / reload
→ verify active revision
```

If compilation or activation fails, the database remains authoritative but system health must report the generation mismatch and enforcement must fail closed for affected policy paths.

### 31.1 Configuration ingestion and shared Change Plan

Direct CLI mutations, AI-generated commands, and `ConfigurationBundle` input MUST NOT maintain separate policy/mutation implementations.

```text
direct public CLI ─┐
AI-generated CLI  ─┼→ canonical Change Plan → validate → resolve → test → diff
ConfigurationBundle┘                       → impact → confirm → concurrency check
                                            → authoritative transaction
                                            → revision/audit → compile/activate/verify
```

The authoritative state remains SQLite. A YAML document is an input/change-set artifact, not a continuously reconciled state owner.

Bundle semantics:

```text
resource omitted → unchanged
state: present   → idempotent create/update
state: absent    → explicit delete subject to reference/destructive checks
same bundle/effective state → NO CHANGE
```

A Change Plan is revision-bound. If state changes after planning, commit fails with a revision conflict rather than silently rebasing security-relevant intent.

The bundle path cannot write authoritative tables, generated runtime JSON, or legacy state through an alternate implementation. It must invoke the same domain mutations and safety checks as canonical public CLI.

Export is redacted and never emits enrollment tickets, install URLs containing credentials, OAuth/static bearer secrets, private keys, or Agent identity private material.

Existing Agent Host local target/service mutations that are not remotely supported return `CLIENT_ACTION_REQUIRED`; the server must never report false success.

Full schema/CLI/audit semantics are defined by `CONFIGURATION_BUNDLE.md`.

### 31.2 Zero-Touch planning and bounded ticket issuance

Configuration intent and enrollment secret issuance are separate operations.

A ConfigurationBundle may create enrollment plans, but applying it creates zero raw tickets. A DRLink Agent and its Managed Host identity continue to materialize only after successful enrollment.

Server-enforced ticket rules:

```text
one issuance request        ≤ 10 tickets
active + unused tickets     ≤ 10 total
one ticket                  = one intended enrollment context
use count                   = 1
TTL default                 = 1 hour
TTL maximum                 = 24 hours
raw ticket/install URL      = display once
stored server credential    = verifier/hash only
successful consume          = atomic
```

If 3 active unused tickets remain, the next issuance can create at most 7. Expired/revoked tickets leave the active-unused count; consuming/expiring an enrollment ticket never disconnects an already enrolled Managed Host.

Neither configuration fields nor hidden/public CLI flags may raise these server-side ceilings.

## 32. Migration framework

Database evolution uses ordered migrations recorded in `schema_migrations`.

Upgrade flow:

```text
pre-upgrade consistent backup
→ compatibility check
→ BEGIN IMMEDIATE
→ apply ordered migrations
→ PRAGMA foreign_key_check
→ integrity validation
→ update migration ledger
→ COMMIT
→ compile policy/runtime artifacts
→ reload
→ verify active generation
```

An older binary encountering a newer unsupported schema must fail closed with a clear diagnostic. It must never guess how to interpret unknown schema.

Legacy JSON files are migration inputs only during the implementation transition. They are not retained as dual authoritative stores.

## 33. Backup and restore

Do not back up a live WAL database with a naive file copy.

Use the SQLite Online Backup API or an equivalent consistent snapshot mechanism.

A product backup includes the state required for recovery, including:

- SQLite snapshot.
- Product configuration.
- PKI/public trust metadata.
- Required root-owned secret files or secret references.
- Version/provenance metadata needed to validate restore compatibility.

Restore flow:

```text
validate archive
→ stop or quiesce affected mutation paths
→ consistent pre-restore safety snapshot
→ restore DB/config/secrets with ownership and modes
→ validate DB integrity + foreign keys + schema
→ compile runtime artifacts from DB
→ atomically activate
→ verify generation and services
→ run diagnostics
```

A backup never treats derived runtime JSON as the canonical recovery source.

## 34. Secret storage

SQLite is the control-plane SSOT, not necessarily the raw secret store.

Secrets such as CA private keys, TLS private keys, raw transport credentials, and short-lived bootstrap secrets may remain in root-owned files or a future OS secret store.

The database may store:

```text
secret reference
credential identifier
hash
status
creation/rotation metadata
```

Raw secret material must not be exposed through normal `show`, audit, completion, support bundles, or policy test output.

## 35. AI Access and MCP Bridge

MCP is part of the v2.4.0 target architecture.

The server hosts a small MCP bridge/control component. Internal endpoints do not each run a separate MCP server.

```text
ChatGPT / Claude / Cursor / MCP Host (target examples until host E2E is evidenced)
                │
          MCP over HTTPS
                │
                ▼
        Data Relay Link Server
             MCP Bridge
                │
          AI Policy Engine
                │
     existing DRLink control path
                │
        Managed Host
                │
       private / closed host
```

MCP does not bypass the existing client identity or transport boundary. The bridge dispatches authorized operations through a dedicated authenticated Data Relay Link management/RPC path implemented by the existing client agent; Remote Services and exposed SSH are not prerequisites for an approved AI operation.

## 36. MCP protocol baseline

Implementation must target the then-current official Model Context Protocol specification and supported SDKs, re-verified immediately before coding and interoperability qualification.

As of the architecture freeze in September 2026, the official MCP `2026-07-28` revision uses an HTTP-native/stateless protocol core for modern remote requests, and Streamable HTTP is the modern remote transport. Legacy HTTP+SSE is not the target for new implementation.

Modern 2026-07-28 requests do not use `initialize`, `notifications/initialized`, `Mcp-Session-Id`, or protocol `ping`. Capability discovery is `server/discover`. Identity is never taken from `_meta.clientInfo`.

Do not hard-code assumptions from older MCP revisions when the current standard provides a different authorization, transport, or operation model.

## 37. AI Identity

Public noun: **AI Identity**. Storage remains `ai_principals`.


AI identity is not a Network Object.

Canonical public resource:

```text
AI Identity
```

Examples:

```text
chatgpt-support
claude-ops
cursor-dev
```

Conceptual fields:

```text
id
name
provider_or_type
enabled
credential_reference_or_subject
created_at
updated_at
last_seen
row_version
```

Authentication credentials are never stored or displayed as plaintext merely for CLI convenience.

## 38. AI Access rules

AI Access is a policy family over authenticated AI Identities. Its public policy semantics are the same BLACKLIST / WHITELIST + Enforcement model used by the other access-policy families.

Canonical public rule shape:

```text
name
source      → AI Identity
destination → Network Object / Network Group
permission  → Permission Object / Permission Group
enabled / disabled
```

Authentication happens before authorization. A display name alone is not an authenticated AI Identity.

Policy evaluation:

```text
No Policy
→ effective policy ALLOW
→ authentication is still mandatory

BLACKLIST
→ any enabled matching Rule DENY
→ no enabled Rule match ALLOW

WHITELIST
→ any enabled matching Rule ALLOW
→ no enabled Rule match DENY

Enforcement DISABLED
→ effective policy ALLOW ALL
→ saved Mode/Rules preserved
→ authentication is still mandatory
```

AI Access Rules are not ordered and do not carry a per-rule ALLOW/DENY action.

Fine-grained operations such as `exec`, `read_file`, `write_file`, `upload_file`, and `download_file`, including applicable path/operation constraints, are represented by Permission Objects / Permission Groups and are enforced on every new invocation.

Targets are resolved through the canonical Network Object / Network Group model. Managed Hosts may participate through their Network Object projection where the AI Access destination rules permit it.

## 39. Initial MCP capability surface

The implementation review should support at least the following target capabilities, subject to real interoperability and security validation:

```text
list_hosts
get_host
get_system_info
exec
read_file
write_file
upload_file
download_file
list_processes
```

The minimum product requirement includes:

```text
exec
read_file
write_file
upload_file
download_file
```

Capabilities are explicit policy grants. Unknown or ungranted tools are denied.

## 40. AI path scopes and exec constraints

File capabilities may be scoped to allowed path patterns.

Example:

```text
Allowed paths:
  /etc/vendor/**
  /opt/vendor/**
  /var/log/vendor/**
```

`exec` is a qualitatively stronger permission. A shell can often modify the filesystem even if direct `write_file` is denied.

Therefore:

```text
true read-only AI role => exec=false
```

When `exec=true`, the target OS account, filesystem permissions, sudo policy, namespaces/sandboxing if used, command timeout, environment filtering, and process controls become part of the security boundary. Execution identity and privilege elevation should be explicit constraints where supported; granting `exec` alone never implies permission to elevate privileges.

## 41. AI authorization timing

Every new MCP tool invocation evaluates the current AI Access policy and current target identity.

Canonical rule:

> **Policy changes apply immediately to new operations.**

A long-running tool operation already authorized is not implicitly terminated by a later policy edit unless an explicit cancellation mechanism is invoked.

## 42. AI audit

AI activity records at least:

```text
timestamp
AI Identity
target Managed Host
client identity
tool
matched rule
result
duration
configuration revision
```

For `exec`, store bounded/sanitized command metadata or a fingerprint and exit status, not unrestricted sensitive output by default.

For file operations, store path, direction, byte count, result, and policy attribution, not file contents.

## 43. MCP authentication boundary

Remote MCP access requires authenticated HTTPS and a current-standard authorization design. The implementation must not invent a proprietary trust shortcut simply because the endpoint is an MCP server.

Requirements:

- Strong AI Identity binding.
- Credential rotation/revocation.
- No anonymous privileged tool calls.
- Server-side authorization on every operation.
- Least-privilege capabilities and target scopes.
- Protection against confused-deputy behavior.
- Rate/resource limits.
- Audit attribution to the effective AI Identity.

Exact OAuth/OIDC/token mechanics are selected during implementation after verifying current MCP host support for ChatGPT, Claude, Cursor, and other supported clients.

Authorization-server strategy (v2.4.0 MCP public-endpoint closure):

```text
Strategy A — Data Relay Link built-in minimal OAuth 2.1 authorization service
plus Static Bearer as a separately named authentication mode.
```

Why A, not only an external AS:

```text
lightweight
no extra DB daemon
1–50 clients
CLI-first operator consent
strong AI Identity binding
no general identity-management product
```

Mechanics:

```text
Auth model: static-bearer+built-in-oauth2.1-as/rs+rfc9728

Static Bearer     operator-issued drk_ token in Authorization: Bearer
                  (not OAuth)

OAuth             Data Relay Link is both the built-in OAuth 2.1
                  authorization server and the MCP resource server.
                  RFC 9728 Protected Resource Metadata
                  RFC 8414 authorization-server metadata
                  RFC 9207 iss on authorization responses
                  authorization_code + PKCE S256
                  refresh_token rotation (drref_) + offline_access metadata
                  RFC 7591 Dynamic Client Registration (/oauth/register)
                  Client ID Metadata Documents (CIMD) when advertised
                  client_credentials with RFC 8707 resource
                  resource-bound expiring drauth_ access tokens
                  AI Identity mapping is explicit and revocable
```

`client_credentials` exists for machine/API MCP clients that can present
`client_id` plus the AI Identity's Static Bearer as `client_secret` and receive a
short-lived resource-bound `drauth_` access token. That access token is not the
Static Bearer token. Cursor typically uses Static Bearer headers.
Claude/ChatGPT custom connectors are expected to use authorization_code+PKCE,
with DCR or CIMD for client registration and refresh tokens for persistent
sessions. DCR/CIMD clients remain unbound until an operator approves OAuth
consent against a concrete AI Identity (`system credential approve-oauth
<PENDING-ID> [AI-IDENTITY]`).

Issuer, resource, authorization endpoint, token endpoint, registration
endpoint, and Protected Resource Metadata are taken from the configured
control-plane public identity.
They are not derived from an arbitrary request `Host` or `X-Forwarded-*` header.

Threat model (must remain fail-closed):

```text
public MCP only at https://<control-host>/mcp
backend remains 127.0.0.1:6103
do not bind 0.0.0.0:6103
do not expose MCP /healthz publicly
TLS terminates on the existing single-443 frontend
Host/X-Forwarded-* from direct clients are not used for issuer/resource identity
Origin is validated to block loopback DNS rebinding
Bearer tokens never appear in show/status/audit/support bundles
OAuth codes are one-time; tokens expire and are resource-bound
issuer and audience/resource mismatches are rejected
authenticated != authorized; AI Access remains fail-closed under current BLACKLIST/WHITELIST semantics
```

## 44. Runtime health and consistency

System status must make revision divergence visible.

Example:

```text
DB Revision       : 42
Remote Policy     : 42 active
Internet Policy   : 42 active
AI Policy         : 42 active
```

A plane at revision 41 while the DB is at 42 must not render simply as Healthy.

The control plane should expose enough metadata to diagnose:

- compile failure.
- activation failure.
- stale generation.
- database integrity failure.
- unsupported schema.
- missing referenced endpoint/service.

## 45. Failure behavior

Fail closed for ambiguous or invalid security state, including:

```text
DB corruption
foreign-key violation
unsupported schema
invalid Network Object value
invalid Network Group membership for the selected field
invalid context assignment
missing referenced Network Object, Service Object, or Permission Object
runtime generation mismatch where safe enforcement cannot be proven
unsafe DNS result
AI Identity authentication failure
unknown AI capability
path-scope violation
```

Do not silently fall back to legacy JSON, `main`, a default allow, or a newly created identity.

## 46. CLI architecture boundary

The canonical guided menus are the Server and Agent Host menus in `Data Relay Link CLI Information Architecture.md`. An older Clients / Objects root is not the current public menu.

The canonical direct roots remain action-oriented:

```text
show
set
unset
test
system
menu
help
exit
```

The CLI IA and command grammar are defined in:

```text
docs/Data Relay Link CLI Information Architecture.md
docs/CLI_REFERENCE.md
```

The old public nouns `acl`, `service-profile`, and `internet-profile` are not canonical v2.4.0 target resources.

## 47. Security-impact confirmation

Interactive confirmation is required for meaningful access broadening.

Example:

```text
Policy behavior will change

Adding to Network Object external2:
  openai.com

Affected Internet Access rule allow-web
  Access broadened under the current policy mode

Continue? [y/N]:
```

Automated/direct workflows require an explicit non-interactive acknowledgement mechanism defined by implementation; they must not bypass the impact check silently.

## 48. Release transition from legacy state

The v2.4 target does not use these as public authority:

- `registry.json` as control-plane authority.
- `egress-control.json` as control-plane authority.
- legacy `service-profile` public resource.
- legacy `internet-profile` public resource.
- legacy ACL public model.
- a v2.4.x MCP exclusion as product policy.

The authoritative store is embedded SQLite. Do not maintain dual writes that treat legacy JSON as a second control-plane authority. A one-time migration may protect existing lab state.

## 49. Stable-release qualification gates

The final exact HEAD must prove at least:

```text
CONTROL_PLANE_DB=PASS
NETWORK_OBJECT_MODEL=PASS
SERVICE_OBJECT_MODEL=PASS
PERMISSION_OBJECT_MODEL=PASS
MANAGED_HOST_MODEL=PASS
ENDPOINT_ADDRESS_INVENTORY=PASS
REMOTE_SERVICE_MODEL=PASS

REMOTE_ACCESS_POLICY=PASS
INTERNET_ACCESS_POLICY=PASS
AI_ACCESS_POLICY=PASS
BLACKLIST_WHITELIST_SEMANTICS=PASS
NO_RULE_ORDERING=PASS
NO_PER_RULE_ACTION=PASS
INITIAL_NO_POLICY_ALLOW=PASS

POLICY_IMPACT_ANALYSIS=PASS
REFERENCE_PROTECTION=PASS
CONCURRENT_EDIT_PROTECTION=PASS

MCP_BRIDGE=PASS
MCP_AUTH=PASS
MCP_HOST_ROUTING=PASS
MCP_CAPABILITY_ENFORCEMENT=PASS
MCP_FILE_SCOPE=PASS
MCP_AUDIT=PASS
MCP_REAL_E2E=PASS

SQLITE_MIGRATION_FRAMEWORK=PASS
TRANSACTIONAL_MUTATION=PASS
REVISION_AUDIT=PASS
RUNTIME_GENERATION_CONSISTENCY=PASS
BACKUP_RESTORE=PASS
DB_CORRUPTION_FAIL_CLOSED=PASS
UPGRADE_MIGRATION=PASS

CLI_IA=PASS
FRESH_INSTALL=PASS
UNINSTALL_ZERO_RESIDUE=PASS
REINSTALL=PASS
MULTI_HOST_REAL_E2E=PASS
FULL_REAL_E2E_PASS_1=PASS
FULL_REAL_E2E_PASS_2=PASS
PASS1_HEAD==PASS2_HEAD
```

Any product/dependency code change between the two final Full Real E2E passes resets the pass counter.

## 50. Explicit non-goals for this architecture phase

The foundation does not require these before v2.4.0 stable:

```text
Web UI
central multi-server SaaS control plane
PostgreSQL/MySQL/Redis service
HA database cluster
hundreds/thousands-endpoint orchestration
SIEM/reporting platform
automatic firewall rule changes
automatic DNS changes
```

Those can be added later without replacing the local SQLite control plane or the current public object and policy identity model.

## 51. Architecture freeze rule

Changes after this document is adopted are classified as:

```text
FOUNDATION CHANGE
  changes identity, schema authority, policy-mode semantics,
  MCP trust boundary, or backup/migration contract

IMPLEMENTATION DETAIL
  changes internal module layout, serialization, query shape, UI spacing,
  or another detail that preserves this contract
```

A foundation change requires an explicit architecture decision before implementation. Implementation details do not.

## 52. Documentation migration map

The v2.4.0 architecture closure classifies repository documents as follows.

### Canonical and rewritten for the new architecture

```text
docs/CONTROL_PLANE_ARCHITECTURE.md
  INTERNAL — schema and migration history; public semantics follow the Product Master

docs/PRODUCT_MASTER.md
  REPLACED/REWRITTEN — product-level SSOT aligned to three access planes

docs/Data Relay Link CLI Information Architecture.md
  REPLACED/REWRITTEN — Managed Host, Network/Service/Permission Objects, and access-policy navigation

docs/CLI_REFERENCE.md
  REPLACED/REWRITTEN — target v2.4 direct grammar

docs/CONFIGURATION_BUNDLE.md
  NEW — declarative change-set, shared Change Plan, AI copy/paste, and bounded Zero-Touch contract

docs/CONTROLLED_EGRESS.md
  REWORKED — low-level Internet Access behavior retained, policy authority replaced

docs/SECURITY.md
  REPLACED/REWORKED — SQLite, runtime generation, and MCP trust boundaries

docs/DATA_RELAY_ROADMAP.md
  REPLACED/REWORKED — implementation sequence for the new foundation

docs/VERSION_POLICY.md
  MODIFIED — old v2.4 MCP exclusion superseded

docs/RELEASE_CHECKLIST.md
  REPLACED/REWORKED — new release gates

docs/RELEASE_VALIDATION.md
  REPLACED/REWORKED — new validation matrix

README.md
  REWRITTEN — concise development-state entry point

CHANGELOG.md
  MODIFIED — Unreleased target scope aligned to the architecture
```

### Retained with targeted update

```text
docs/DEPLOYMENT_MODES.md
  RETAIN — topology behavior remains useful; persistent-state wording updated to SQLite
```

### Historical / superseded

```text
docs/SCHEMA_V2_DEPLOYMENT.md
  HISTORICAL — old JSON registry schema-v2 runbook; no longer v2.4 authority
```

### Retained but non-canonical implementation/platform documents

The following remain useful for their narrower platform, lab, or historical purpose and do not redefine control-plane architecture:

```text
docs/FRP_UPGRADE.md
docs/MACOS_CLIENT.md
docs/WINDOWS_CLIENT.md
docs/WINDOWS_CLIENT_DESIGN.md
docs/ZERO_TOUCH_SHORT_URL.md
docs/OCI_ACCEPTANCE.md
docs/PRIVILEGE_SEPARATION_DEFERRED.md
```

If implementation changes make commands or state references in those files stale, update or archive them during the implementation/qualification phase. They must not override the canonical documents above.

### Release metadata after MCP implementation

The old `MCP_V2_4_EXCLUSION` / `features.mcp_included=false` guard is retired. Qualified v2.4.0 candidate metadata uses `MCP_V2_4_INCLUDED_AND_QUALIFIED` and `features.mcp_included=true` only when the MCP Bridge and AI Access plane are present in the candidate bytes.
