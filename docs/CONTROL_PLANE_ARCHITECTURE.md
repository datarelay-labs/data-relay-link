# Data Relay Link v2.4.0 — Control Plane, Policy, and MCP Architecture

> **Document role:** Canonical technical architecture SSOT for the v2.4.0 control-plane redesign
> **Status:** Approved target architecture; implementation and release qualification pending
> **Product:** Data Relay Link
> **Phase:** `V2_4_0_CONTROL_PLANE_POLICY_AND_MCP_ARCHITECTURE_CLOSURE`
> **Applies to:** Server control plane, Objects, Managed Endpoints, Published Services, Remote Access, Internet Access, AI Access/MCP, audit, backup/restore, runtime compilation, and release qualification

## 1. Purpose and authority

This document freezes the architecture that Data Relay Link must implement before v2.4.0 may become stable.

The v2.4.0 branch is still pre-stable. There are no production users whose compatibility requirements justify preserving the legacy JSON state, ACL grammar, Internet Profile model, Service Profile model, or MCP exclusion. The goal is therefore to complete the durable foundation now rather than carry avoidable migration debt into a stable release.

Authority order:

1. Actual qualified runtime behavior on an exact Git HEAD.
2. This architecture plus `PRODUCT_MASTER.md` for the approved v2.4.0 target.
3. `VERSION_POLICY.md` and release governance.
4. Canonical CLI IA and CLI reference.
5. Detailed operator documentation.

Until implementation is complete, documentation may describe an approved target that the current development HEAD does not yet implement. Such sections must not be presented as released behavior.

## 2. Architecture invariants

The following are non-negotiable for v2.4.0:

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
   Published Service    proxy / fixed TCP       MCP Bridge
          │                    │                    │
   Managed Endpoint     policy compiler         Managed Endpoint
      or ROUTED target    / runtime artifact       / target host
```

Policy authorization and physical reachability are separate. A rule ALLOW does not create a service, route, connector, or listening socket by itself.

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

Recommended table families:

```text
Core
  schema_migrations
  system_meta
  config_revisions
  revision_snapshots
  audit_events
  runtime_generations

Objects
  objects
  object_values
  object_group_members

Clients
  clients
  managed_endpoints
  endpoint_addresses
  client_groups
  client_group_members
  client_tags

Services
  published_services
  service_presets
  port_reservations

Network Policy
  policy_rules
  rule_sources
  rule_destinations
  rule_services

Enrollment / Lifecycle
  enrollments

AI / MCP
  ai_principals
  ai_access_rules
  ai_rule_targets
  ai_rule_capabilities
  ai_path_scopes
  ai_exec_constraints
  ai_sessions
  ai_activity
```

Exact DDL belongs to implementation, but identity, foreign-key, revision, and fail-closed semantics in this document are normative.

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

Renaming an Object, Rule, Client Group, or other display entity must not break references.

Interactive workflows read the current `row_version` and must reject a commit if another writer changed that entity in the meantime.

Example failure:

```text
Object changed while you were editing it.
No changes were applied.
Review current state and retry.
```

## 8. Neutral Object model

Data Relay Link does not have separate Source Object and Destination Object resource types.

Canonical user resources:

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

## 9. Object types

Canonical initial kinds:

```text
Host
Network
FQDN
Managed Endpoint
Group
```

Static Objects use `origin=static`. Managed Endpoint objects use `origin=managed` and are lifecycle-managed by Data Relay Link.

Objects may contain multiple values when those values form one logical administrative object. Operators are not forced to create one Object per IP/CIDR merely to group them immediately afterward.

## 10. Object Group semantics

Object Groups are reusable collections of Objects and, if implemented, nested Object Groups.

Required behavior:

- Immutable member references.
- Nested group cycle detection.
- No silent pruning of invalid members for a policy context.
- Assignment is fail-closed if any member makes the group invalid for the selected field.
- Referenced groups cannot be cascade-deleted.

Cycle example that must be rejected:

```text
A → B → C → A
```

## 11. Context validation

Neutral does not mean every Object type is legal everywhere.

Initial context policy:

```text
Remote Access Source
  Host | Network | compatible Object Group

Remote Access Destination
  Host | Network | Managed Endpoint | compatible Object Group

Internet Access Source
  Host | Network | compatible Object Group

Internet Access Destination
  FQDN | Host | public Network | compatible Object Group
```

Exact validation rules are compiled from one canonical type/context matrix and reused by the CLI, policy validator, test/explain path, and runtime compiler.

Tab completion and guided selectors should show only context-valid candidates.

## 12. Managed Endpoint

A connected/enrolled Data Relay Link Client is represented by a managed Object.

Example:

```text
Managed Endpoint: dp1
Client ID: facc9a57
Status: Connected
```

Managed Endpoints appear in normal Object discovery but are not manually created with `set object` and are not manually deleted with `unset object`.

Attempting to remove one through Object CRUD must fail and direct the operator to the appropriate Client lifecycle operation.

## 13. Orphaned Managed Endpoints

If a Client is removed while policy still references its Managed Endpoint identity, Data Relay Link must not silently reinterpret the reference or bind it to a new machine with the same label.

A referenced endpoint may remain as an orphaned identity:

```text
Status: Orphaned
Reason: Client removed
```

A newly enrolled machine receives its own immutable identity. Label reuse never implies identity reuse.

## 14. Endpoint address inventory

A server-observed source address can be a NAT/public address and is not sufficient to determine internal Network membership.

Clients therefore report an inventory of local addresses through enrollment, heartbeat, or management synchronization.

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

## 15. Client Group vs Object Group

These are separate concepts:

```text
Client Group
  operational organization of clients/endpoints

Object Group
  reusable network-policy object collection
```

The old generic public `group` name should become `client-group` where ambiguity exists.

AI Access targets may reference Managed Endpoints and Client Groups. A third AI-specific host group is unnecessary.

## 16. Published Service

Inbound relay definitions are called **Published Services** to distinguish them from firewall-style protocol/port service criteria.

A Published Service records at least:

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

## 17. Published Service target modes

Canonical modes:

```text
SELF
ROUTED
```

### SELF

The effective destination is the Managed Endpoint itself, even if the local process target is `127.0.0.1`.

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

The Managed Endpoint acts as the connector to another reachable host/service.

Example:

```text
web1
  Target Mode      : ROUTED
  Effective Target : 10.10.10.20
  Via              : dp1
  Port             : 443
```

The routed target does not require its own Data Relay Link agent.

## 18. Effective Remote Access

Authorization does not expose arbitrary destinations inside a matching subnet.

Effective access is the intersection:

```text
Rule Match
+
Enabled Published Service
+
Reachable Connector / target
=
Effective Remote Access
```

A broad destination Object therefore does not automatically publish every address or port in that Object.

## 19. Service Preset

The old **Service Profile** public concept is replaced by **Service Preset**.

A preset is only a creation convenience. It pre-fills values when a Published Service is created. It does not own the created service and changing the preset later does not mutate existing services.

Service Presets do not participate in policy evaluation.

## 20. Remote Access rulebase

Remote Access is an ordered rulebase.

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

## 21. Internet Access rulebase

Internet Access is a separate ordered rulebase.

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

## 23. Explicit DENY and implicit DENY

Both network rulebases support:

```text
ALLOW
DENY
```

An explicit DENY enables ordered exception policy. The final implicit rule is always DENY and is not deletable.

## 24. Safe rule creation and ordering

New rules are created:

```text
Disabled
+
Rulebase bottom
```

Ordering is manipulated by relationship rather than requiring the user to maintain numeric sequence values:

```text
set remote-access <RULE> before <RULE>
set remote-access <RULE> after <RULE>
set internet-access <RULE> before <RULE>
set internet-access <RULE> after <RULE>
```

Internal sparse positions such as 1000/2000/3000 are acceptable. Human output may render them as 10/20/30.

## 25. Shadow and conflict analysis

Overlapping rules are valid. They are not rejected merely because they conflict.

The policy analyzer must detect cases such as:

- Fully shadowed rule.
- Partially shadowed rule where practical to determine.
- Earlier rule changing the effective action of a later candidate.
- Object or group edits that introduce new shadowing.

Example explanation:

```text
Rule #20 block-google is shadowed by #10 allow-all.
Traffic matches #10 first.
Effective action: ALLOW
```

## 26. Policy impact analysis

Mutations to referenced entities can change effective access even when no Rule row changes.

Before committing security-relevant changes, analyze at least:

```text
Access broadened
Access narrowed
Affected active rules
New shadowing
Removed shadowing
Effective action changes
```

Broadening requires explicit confirmation in interactive workflows.

Impact analysis applies to:

- Object values.
- Object Group membership.
- Rule source/destination/service/action/order/enablement.
- Published Service target or mode.
- Managed Endpoint address inventory changes when they alter policy membership.
- AI target/capability/path scope changes.

## 27. Reference protection

Referenced Objects, Object Groups, Managed Endpoint identities, and other durable dependencies are not cascade-deleted.

Deletion must fail with references listed, for example:

```text
Cannot remove Object.
Referenced by:
  remote-access #10 partner-ssh
  internet-access #20 approved-web
```

The operator removes or changes references first.

## 28. Test and explain UX

Policy debugging uses actual flow inputs.

Remote Access example:

```text
test remote-access 203.0.113.10 10.10.10.50 tcp 22
```

Internet Access example:

```text
test internet-access 10.10.10.20 google.com 443 https
```

Output must show:

- Source Object matches.
- Destination Object matches.
- Rule evaluation order.
- First complete match.
- Effective action.
- Relevant Published Service / reachability state for Remote Access.
- Final authorization result.

`test` is an explain/simulation operation unless the command explicitly says it performs live connectivity.

## 29. Revision model

Every material authoritative control-state mutation belongs to one committed revision. Repeated heartbeat timestamp refreshes that do not change effective state need not consume a revision; a material endpoint-address set change does because it can change policy membership and runtime generation.

Conceptual record:

```text
Revision 42
Actor   : root
Command : set object external2 value openai.com
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
rules_shadowed
effective_action_changes
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

Export is redacted and never emits enrollment tickets, install URLs containing credentials, OAuth/static bearer secrets, private keys, or client identity private material.

Existing-client local target/service mutations that are not remotely supported return `CLIENT_ACTION_REQUIRED`; the server must never report false success.

Full schema/CLI/audit semantics are defined by `CONFIGURATION_BUNDLE.md`.

### 31.2 Zero-Touch planning and bounded ticket issuance

Configuration intent and enrollment secret issuance are separate operations.

A ConfigurationBundle may create enrollment plans, but applying it creates zero raw tickets. Client and Managed Endpoint identity continue to materialize only after successful enrollment.

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

If 3 active unused tickets remain, the next issuance can create at most 7. Expired/revoked tickets leave the active-unused count; consuming/expiring an enrollment ticket never disconnects an already enrolled Client.

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
        Managed Endpoint
                │
       private / closed host
```

MCP does not bypass the existing client identity or transport boundary. The bridge dispatches authorized operations through a dedicated authenticated Data Relay Link management/RPC path implemented by the existing client agent; Published Services and exposed SSH are not prerequisites for an approved AI operation.

## 36. MCP protocol baseline

Implementation must target the then-current official Model Context Protocol specification and supported SDKs, re-verified immediately before coding and interoperability qualification.

As of the architecture freeze in September 2026, the official MCP `2026-07-28` revision uses an HTTP-native/stateless protocol core for modern remote requests, and Streamable HTTP is the modern remote transport. Legacy HTTP+SSE is not the target for new implementation.

Modern 2026-07-28 requests do not use `initialize`, `notifications/initialized`, `Mcp-Session-Id`, or protocol `ping`. Capability discovery is `server/discover`. Identity is never taken from `_meta.clientInfo`.

Do not hard-code assumptions from older MCP revisions when the current standard provides a different authorization, transport, or operation model.

## 37. AI Principal

AI identity is not a Network Object.

Canonical resource:

```text
AI Principal
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

AI authorization is a separate policy family because its semantics are capability-oriented rather than packet-oriented. It still uses deterministic ordered policy evaluation.

Example:

```text
AI Access Rule: readonly-audit
Principal: chatgpt-support
Targets: production-linux
Capabilities:
  read_file
  get_system_info
Paths:
  /etc/**
  /var/log/**
Action: ALLOW
Enabled: yes
```

Canonical evaluation:

```text
disabled rules are skipped
top-down
first complete match wins
explicit ALLOW / DENY
implicit final DENY
```

A complete AI match means Principal AND Target AND requested Capability AND any applicable path/operation constraints match. Multiple target selectors within one rule are OR; multiple capabilities within one rule are OR. Constraints narrow a match and never grant permission by themselves. New AI rules are created disabled at the bottom and can be moved with before/after semantics.

Targets:

```text
Managed Endpoint
Client Group
```

A separate AI Host Group is not introduced.

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

Every new MCP tool invocation evaluates the current ordered AI Access rules and current target identity.

Canonical rule:

> **Policy changes apply immediately to new operations.**

A long-running tool operation already authorized is not implicitly terminated by a later policy edit unless an explicit cancellation mechanism is invoked.

## 42. AI audit

AI activity records at least:

```text
timestamp
principal
target Managed Endpoint
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

- Strong principal binding.
- Credential rotation/revocation.
- No anonymous privileged tool calls.
- Server-side authorization on every operation.
- Least-privilege capabilities and target scopes.
- Protection against confused-deputy behavior.
- Rate/resource limits.
- Audit attribution to the effective AI Principal.

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
strong AI Principal binding
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
                  AI Principal mapping is explicit and revocable
```

`client_credentials` exists for machine/API MCP clients that can present
`client_id` plus the principal's Static Bearer as `client_secret` and receive a
short-lived resource-bound `drauth_` access token. That access token is not the
Static Bearer token. Cursor typically uses Static Bearer headers.
Claude/ChatGPT custom connectors are expected to use authorization_code+PKCE,
with DCR or CIMD for client registration and refresh tokens for persistent
sessions. DCR/CIMD clients remain unbound until an operator approves OAuth
consent against a concrete AI Principal (`system credential approve-oauth
<PENDING-ID> <PRINCIPAL>`).

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
authenticated != authorized; AI Access still first-match DENY
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
invalid Object value
invalid group cycle
invalid context assignment
missing referenced Object
runtime generation mismatch where safe enforcement cannot be proven
unsafe DNS result
MCP principal/auth failure
unknown AI capability
path-scope violation
```

Do not silently fall back to legacy JSON, `main`, a default allow, or a newly created identity.

## 46. CLI architecture boundary

The canonical guided root is:

```text
1) Clients
2) Objects
3) Remote Access
4) Internet Access
5) AI Access
6) System
7) Help
8) Exit
```

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

Adding to object external2:
  openai.com

Affected rule #10 allow-web
  Access broadened

Affected rule #20 block-openai
  Will become shadowed

Before: DENY
After : ALLOW via #10

Continue? [y/N]:
```

Automated/direct workflows require an explicit non-interactive acknowledgement mechanism defined by implementation; they must not bypass the impact check silently.

## 48. Release transition from legacy state

The development branch currently contains legacy assumptions such as JSON authoritative state, legacy ACL/Profile nouns, and governance that excludes MCP from v2.4.x.

Those are implementation-transition artifacts, not the approved target architecture.

The implementation phase must remove or replace, at minimum:

- `registry.json` as control-plane authority.
- `egress-control.json` as control-plane authority.
- legacy `service-profile` public resource.
- legacy `internet-profile` public resource.
- legacy ACL public model.
- v2.4.x MCP exclusion checks in code, tests, manifest schema, release scripts, and generated manifest.

Do not maintain dual writes for backward compatibility. A one-time development migration may be used to protect test/lab state, but the stable v2.4.0 architecture has one authority: SQLite.

## 49. Stable-release qualification gates

The final exact HEAD must prove at least:

```text
CONTROL_PLANE_DB=PASS
OBJECT_MODEL=PASS
OBJECT_GROUP_MODEL=PASS
MANAGED_ENDPOINT_MODEL=PASS
ENDPOINT_ADDRESS_INVENTORY=PASS
PUBLISHED_SERVICE_SELF_ROUTED=PASS

REMOTE_ACCESS_RULEBASE=PASS
INTERNET_ACCESS_RULEBASE=PASS
AI_ACCESS_RULEBASE=PASS
FIRST_MATCH_ORDERING=PASS
ALLOW_DENY=PASS
IMPLICIT_DEFAULT_DENY=PASS

SHADOW_DETECTION=PASS
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

Those can be added later without replacing the local SQLite/object/rule identity model.

## 51. Architecture freeze rule

Changes after this document is adopted are classified as:

```text
FOUNDATION CHANGE
  changes identity, schema authority, policy ordering, security semantics,
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
  NEW — technical architecture SSOT

docs/PRODUCT_MASTER.md
  REPLACED/REWRITTEN — product-level SSOT aligned to three access planes

docs/Data Relay Link CLI Information Architecture.md
  REPLACED/REWRITTEN — new Objects / Remote / Internet / AI navigation

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
docs/MORNING_E2E_CHECKLIST.md
docs/MORNING_REAL_E2E_FINAL_CHECKLIST.md
```

If implementation changes make commands or state references in those files stale, update or archive them during the implementation/qualification phase. They must not override the canonical documents above.

### Release metadata after MCP implementation

The old `MCP_V2_4_EXCLUSION` / `features.mcp_included=false` guard is retired. Qualified v2.4.0 candidate metadata uses `MCP_V2_4_INCLUDED_AND_QUALIFIED` and `features.mcp_included=true` only when the MCP Bridge and AI Access plane are present in the candidate bytes.
