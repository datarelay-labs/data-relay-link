# Data Relay Link — Product Master

> **Document role:** Canonical product charter and product-level specification
> **Status:** Normative living document
> **Target release:** v2.4.0 development architecture; stable qualification pending
> **Primary CLI:** `drlink`
> **Technical architecture SSOT:** `docs/CONTROL_PLANE_ARCHITECTURE.md`
> **Version governance:** `docs/VERSION_POLICY.md`

Current project version: **2.4.0**
Current pinned FRP version: **v0.71.0**

## 1. Product definition

Data Relay Link is a lightweight secure connectivity gateway for isolated and restricted networks.

It controls only the connections that are needed rather than joining whole networks.

```text
Remote Access     outside → inside
Internet Access   inside → approved outside destinations
AI Access         authorized AI/MCP principal → approved internal targets/capabilities
```

Core statement:

> **Secure Connectivity for Isolated Networks**

Design principle:

> **Do not connect entire networks. Relay only the connections that are actually needed.**

## 2. Product family

```text
Data Relay
├── Data Relay Control
│   Control what data moves.
└── Data Relay Link
    Control what can connect.
```

This document covers Data Relay Link only.

## 3. v2.4.0 foundation decision

v2.4.0 is still pre-stable. The project deliberately uses this window to complete the long-lived control-plane foundation before an immutable public compatibility promise exists.

The approved v2.4.0 target includes:

```text
embedded SQLite control plane
neutral Objects and Object Groups
Managed Endpoint objects
endpoint local-address inventory
Published Service SELF / ROUTED semantics
ordered Remote Access rules
ordered Internet Access rules
explicit ALLOW / DENY
first-match evaluation
implicit default DENY
shadow/conflict analysis
policy-impact analysis
revision/audit infrastructure
optimistic concurrency
runtime compilation and generation tracking
consistent SQLite backup/restore
AI Access policy
MCP Bridge
ConfigurationBundle declarative change sets
AI-generated canonical CLI / copy-paste configuration blocks
Zero-Touch bounded batch issuance (max 10 active unused, unique single-use tickets)
```

Legacy JSON state and legacy public nouns do not constrain this redesign.

## 4. Canonical product identity

```text
Product         Data Relay Link
CLI             drlink
Prompt          drlink>
Config          /etc/drlink/
State           /var/lib/drlink/
Control DB      /var/lib/drlink/drlink.db
Upstream relay  official fatedier/frp
```

FRP remains an internal/upstream dependency for Remote Access. It is not the product identity and must not leak into normal operator workflows except where explicit upstream-engine attribution is useful.

FRP is pinned, tested, and is not forked. The current v2.4.0 development line pins Relay Engine (FRP) `0.71.0`; product and engine versions remain independent.

## 5. Target scale

Primary operating range:

```text
1–5 clients       extremely simple
10–30 clients     comfortable CLI operation
30–50 clients     Client Groups / tags / filters sufficient
100–1000 clients  not the current product target
```

Do not turn Data Relay Link into a large fleet-management or central SaaS platform merely to match competitor feature lists.

## 6. Product planes

### 6.1 Remote Access

Remote Access exposes only explicitly published internal services.

```text
Outside operator
    ↓
Data Relay Link Server
    ↓
secure relay transport
    ↓
Managed Endpoint / connector
    ↓
Published Service
```

Supported service families remain SSH, HTTP, HTTPS passthrough, and Custom TCP where qualified.

Remote Access authorization is separate from reachability. Effective access requires both a policy ALLOW and an enabled/reachable Published Service.

### 6.2 Internet Access

Internet Access is the product-facing name for Controlled Egress.

Protected hosts can use the Data Relay Link egress gateway to reach only approved destinations.

```text
Protected host
    ↓
HTTP/HTTPS proxy or approved fixed TCP path
    ↓
Data Relay Link Server
    ↓
Internet Access policy
    ↓
approved destination only
```

The base HTTP/HTTPS path remains agentless for the protected host.

### 6.3 AI Access

AI Access provides policy-controlled remote operations through a Data Relay Link MCP Bridge.

```text
ChatGPT / Claude / Cursor / other MCP host (target examples; support is evidence-based)
    ↓
MCP over authenticated HTTPS
    ↓
DRLink MCP Bridge
    ↓
AI Access policy
    ↓
Managed Endpoint / Client Group target
```

Internal hosts do not require a separate MCP server per endpoint. Existing Data Relay Link clients and identities are reused.

## 7. Embedded control plane

Data Relay Link uses embedded SQLite as the authoritative control-plane store:

```text
/var/lib/drlink/drlink.db
```

This does **not** make the product dependent on an external database service.

No PostgreSQL, MySQL, Redis, Kubernetes, or separate management database daemon is required.

The database owns durable identity, relationships, policy, revisions, and audit metadata. Runtime artifacts are derived and compiled from the DB.

## 8. Objects

Network policy uses neutral reusable resources:

```text
Object
Object Group
```

There is no public Source Object or Destination Object type.

Initial Object kinds:

```text
Host
Network
FQDN
Managed Endpoint
Group
```

An Object may contain multiple values when they represent one logical administrative object.

The policy field determines whether an Object is acting as Source or Destination.

## 9. Managed Endpoint

Every enrolled Data Relay Link Client is represented by a lifecycle-managed Managed Endpoint object.

Managed Endpoints:

- have immutable identity.
- are not manually created by `set object`.
- are not manually deleted by `unset object`.
- can remain Orphaned when policy still references a removed client.
- report local address inventory for policy membership and SELF-target semantics.

A new client with the same label never automatically inherits an old Managed Endpoint identity.

## 10. Client Groups and Object Groups

```text
Client Group
  operational organization and AI target selection

Object Group
  reusable collection for network access policy
```

These are distinct public concepts.

The old ambiguous generic `group` resource should become `client-group` where needed.

## 11. Published Services

An inbound relay definition is a **Published Service**.

Canonical target modes:

```text
SELF
ROUTED
```

SELF means the service belongs to the Managed Endpoint itself even when the process is reached through `127.0.0.1`.

ROUTED means the Managed Endpoint acts as a connector to another reachable host/service. The routed target does not need its own agent.

This distinction is mandatory for correct destination-policy matching.

## 12. Service Presets

The old **Service Profile** public resource is replaced by **Service Preset**.

A preset only pre-fills values during Published Service creation. It does not own the created service and later preset changes do not mutate existing services.

## 13. Network policy model

Remote Access and Internet Access are separate ordered rulebases.

Both use:

```text
Top-down evaluation
First complete match wins
Explicit ALLOW
Explicit DENY
Implicit default DENY
```

Rule order is authoritative. There is no hidden specificity-wins algorithm.

New rules are created disabled at the bottom of their rulebase.

Rule movement should use `before` / `after` semantics rather than forcing users to manage numeric indexes.

## 14. Policy safety

The product must explain and constrain changes that alter effective access.

Required safeguards:

```text
shadow/conflict detection
policy-impact analysis
reference protection
context-aware Object validation
Object Group cycle detection
optimistic concurrency
broadening confirmation
```

Object, Object Group, Published Service, endpoint-address, and rule changes can all change effective policy and therefore participate in impact analysis.

## 15. Policy timing

Canonical rule:

> **Policy changes apply immediately to new connections.**

Existing established connections are not implicitly terminated merely because policy changed.

For AI Access, each new MCP tool invocation uses the current policy. A running operation is not implicitly killed by a later policy edit.

## 16. Internet Access security boundary

Internet Access must never become an open proxy.

Required controls include:

- default deny.
- explicit source and destination policy.
- exact FQDN and controlled wildcard handling where supported.
- public Host/CIDR destination support where safe and explicit.
- server-side DNS resolution.
- DNS rebinding resistance.
- SSRF/private/local/metadata destination protection.
- validated exact-IP connection after resolution.
- HTTPS CONNECT/SNI binding as applicable.
- safe protocol and port validation.
- fail-closed policy loading and parsing.
- bounded resource/time-out behavior.
- safe audit logs.

TLS interception is not required for the base design.

## 17. AI principals and AI Access

AI identity is represented by an **AI Principal**, not a Network Object.

Examples:

```text
chatgpt-support
claude-ops
cursor-dev
```

AI Access rules bind:

```text
Principal
Targets: Managed Endpoint / Client Group
Capabilities
Path scopes
Exec constraints
Enabled state
```

Initial required capability set includes:

```text
exec
read_file
write_file
upload_file
download_file
```

Additional target capabilities include host/system/process discovery.

A true read-only AI role must have `exec=false`; shell execution can bypass a nominal direct-file write restriction through ordinary OS operations.

## 18. MCP Bridge

MCP is included in the v2.4.0 target.

The bridge is a small server-side component integrated with Data Relay Link control and client identities, not a new heavyweight management plane.

Implementation must use the current official MCP specification and supported SDKs at coding time, with real interoperability validation for intended clients.

Legacy SSE-first designs are not the new target.

## 19. Security principles

Data Relay Link is default deny and fail closed.

Invalid or ambiguous state is denied rather than guessed.

Examples:

```text
corrupt database
unsupported schema
invalid Object or group
missing durable reference
unsafe DNS result
runtime generation mismatch
unknown AI capability
authentication failure
path-scope violation
```

Secrets are not exposed through normal show/help/completion/audit/support output.

## 20. Revision and audit

Every authoritative mutation belongs to a configuration revision.

Revision/audit infrastructure is shared by network and AI policy families.

Audit records who changed what, the result, and policy impact without storing arbitrary secret material or full sensitive payloads.

The design must support future:

```text
system audit
system revisions
system diff
rollback
```

## 21. Runtime generation

Runtime enforcement derives from compiled artifacts generated from a specific DB revision.

System status must expose whether each plane is active on the expected revision.

A stale or failed generation is not reported as healthy.

## 22. Backup and restore

A live WAL-mode SQLite database is not backed up with a naive `cp`.

Use SQLite Online Backup or an equivalent consistent snapshot mechanism.

Backup includes the SQLite snapshot plus required product configuration, trust material, secret references/files, and provenance metadata.

Restore recompiles runtime state from the DB.

## 23. CLI model

Guided root:

```text
Clients
Objects
Remote Access
Internet Access
AI Access
System
Help
Exit
```

Direct command roots:

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

The old public nouns `acl`, `service-profile`, and `internet-profile` are not canonical v2.4.0 target grammar.

The full UX contract is in `docs/Data Relay Link CLI Information Architecture.md`.

### 23.1 ConfigurationBundle and AI-assisted operations

v2.4.0 stable includes a declarative `ConfigurationBundle` input for multi-resource changes and an AI-friendly copy/paste workflow. This is not a second configuration authority.

```text
direct canonical CLI ─┐
AI-generated CLI     ─┼→ shared Change Plan → validate/test/diff/impact/confirm
ConfigurationBundle ─┘                      → one transaction → revision/audit → compile/activate
```

The server SQLite state remains authoritative. Bundle omission never deletes existing state; deletion is explicit. Reapplying the same bundle is idempotent and must produce `NO CHANGE` when effective state is already equal.

Canonical configuration operations stay under existing direct roots; no top-level `apply` root is reintroduced. File and standard-input workflows are defined in `CONFIGURATION_BUNDLE.md` and `CLI_REFERENCE.md`.

AI output rules:

```text
simple independent change → one canonical public drlink command
multi-resource/dependent change → one ConfigurationBundle block
internal helper/direct DB/runtime JSON → forbidden
secret/ticket/private key in generated bundle → forbidden
```

Zero-Touch deployment intent may be declared by a bundle, but secrets are issued separately immediately before installation. A single issuance request is limited to 10 unique single-use tickets, and the server permits at most 10 active unused tickets at once. Default TTL is 1 hour; maximum TTL is 24 hours.

## 24. Enrollment and identity

Zero-Touch remains the preferred client onboarding path; Manual Enrollment remains available.

Client identity is immutable and separate from hostname/IP/label metadata.

Public service port reservations remain persistent resources unless explicitly released.

Ordinary lifecycle actions must not silently release reservations or rebind identities.

## 25. Public endpoint identity

Preserve the existing separation:

```text
public_ip / public_host
  allocator/control identity

public_hostname
  optional published-service alias

bootstrap_hostname
  optional bootstrap hostname
```

Installer/config generation must choose and reuse the canonical public control endpoint consistently.

## 26. Network responsibility boundary

Data Relay Link does not silently mutate external infrastructure such as cloud security groups, customer firewalls, NAT/DNAT, DNS providers, SSH accounts, or application certificates.

It may validate and explain required external configuration, but external changes remain operator/customer responsibility unless an explicit future feature is approved.

## 27. Platform direction

Server:

```text
Linux primary
```

Client qualification matrix includes:

```text
Ubuntu 24
Rocky Linux 8
Rocky Linux 9
Amazon Linux 2023
macOS Apple Silicon
Windows 10
```

Claims must match real qualification evidence.

## 28. Release model

The current target remains:

```text
PROJECT_VERSION=2.4.0
RELEASE_CHANNEL=development until explicitly promoted
FRP_VERSION=independently pinned
```

MCP is no longer excluded from the v2.4.0 target. Existing code/tests/schema that hard-code MCP exclusion are implementation debt and must be changed before candidate qualification.

No stable tag is created until the complete architecture is implemented and qualified.

## 29. Final release gate

At minimum, v2.4.0 stable requires the final exact HEAD to pass:

```text
SQLite control plane
Object / Object Group / Managed Endpoint model
Endpoint address inventory
Published Service SELF / ROUTED
Remote Access ordered rulebase
Internet Access ordered rulebase
AI Access rulebase
ALLOW / DENY / implicit DENY
first-match ordering
shadow detection
policy-impact analysis
reference protection
optimistic concurrency
revision/audit
runtime generation consistency
backup/restore
migration/corruption fail-closed
MCP Bridge/auth/routing/capability/path/audit
MCP Real E2E
multi-host Real E2E
fresh install/uninstall/reinstall
ConfigurationBundle file/stdin validation, diff, atomicity, idempotency, revision conflict, redacted export, and direct-CLI semantic parity
AI-generated copy/paste ConfigurationBundle Real E2E
Zero-Touch batch limits: max 10/request, max 10 active unused, unique single-use, default 1h/max 24h TTL
Full Real E2E pass 1 and pass 2 on the same exact HEAD
```

Any code or dependency change between the two full passes resets the pass counter.

## 30. Explicit non-goals

Not required for v2.4.0 stable:

```text
Web UI
external database service
central SaaS control plane
HA orchestrator
hundreds/thousands-endpoint fleet orchestration
SIEM/reporting platform
TLS inspection
CASB/DLP
full VPN/network overlay
automatic firewall or DNS management
```

## 31. Documentation ownership

Canonical documents:

```text
PRODUCT_MASTER.md
  product charter and product-level decisions

CONTROL_PLANE_ARCHITECTURE.md
  technical control-plane/policy/MCP SSOT

Data Relay Link CLI Information Architecture.md
  guided CLI terminology and navigation

CLI_REFERENCE.md
  target direct grammar

CONFIGURATION_BUNDLE.md
  declarative configuration, AI copy/paste, Change Plan, and Zero-Touch batch contract

SECURITY.md
  trust boundaries and security invariants

CONTROLLED_EGRESS.md
  Internet Access protocol/security behavior

DEPLOYMENT_MODES.md
  Direct / Enterprise single-443 topology and transport deployment details

VERSION_POLICY.md
  version/release governance

RELEASE_CHECKLIST.md / RELEASE_VALIDATION.md
  qualification evidence and gates
```

Historical behavior belongs in Git history or explicitly historical documents, not in the current Product Master as active product truth.

## 32. Decision log

### 2026-09 — SQLite control plane before stable

**Decision:** Use embedded SQLite as the authoritative local control plane before v2.4.0 stable.

**Reason:** Object relationships, ordered rules, audit, revisions, backup, and MCP authorization are better represented transactionally than as multiple authoritative JSON files.

### 2026-09 — Neutral Objects

**Decision:** Use reusable Object/Object Group resources; Source/Destination role comes from rule context.

### 2026-09 — Ordered rulebases

**Decision:** Remote Access and Internet Access use top-down first-match ordered rules with explicit ALLOW/DENY and implicit default DENY.

### 2026-09 — Managed Endpoint and SELF/ROUTED

**Decision:** Client identity is represented by Managed Endpoint; Published Service distinguishes SELF from ROUTED effective targets.

### 2026-09 — Policy-impact analysis

**Decision:** Rule and referenced-entity mutations are analyzed for effective access changes before commit.

### 2026-09 — MCP included in v2.4.0 target

**Decision:** Supersede the earlier v2.4 MCP-exclusion decision and include the MCP Bridge/AI Access foundation before stable release.

**Reason:** This is still a pre-stable architecture window, so adding the authorization foundation now avoids a second control-plane redesign immediately after stable release.

### 2026-09 — ConfigurationBundle and bounded Zero-Touch before stable

**Decision:** Include declarative ConfigurationBundle input and AI copy/paste workflows in the v2.4.0 stable target rather than deferring them to v2.5.0.

**Reason:** CLI and configuration-file automation must share one Change Plan/control-plane engine from the first stable release; adding a separate configuration path later would create avoidable semantic and migration debt. Zero-Touch secret issuance remains separate from configuration intent and is bounded to unique single-use tickets with server-enforced batch/active limits.

## 33. Master rule

Before adding any feature, ask:

> Does this improve Data Relay Link at safely and simply permitting only the required connection, destination, or AI operation?

Then ask:

> Can it be added without breaking the local SQLite/identity/policy foundation?

If the answer points toward unnecessary platform expansion, defer it unless real field demand justifies the scope.
