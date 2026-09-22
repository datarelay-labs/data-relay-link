# Data Relay Link — Product Master

> **Document role:** Canonical product charter and product-level specification
> **Status:** Normative living document
> **Target release:** v2.4.0 development; stable qualification pending
> **Primary CLI:** `drlink`
> **CLI/AI SSOT:** `docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`
> **Version governance:** `docs/VERSION_POLICY.md`

Current project version: **2.4.0**

Development builds must display an identity equivalent to `2.4.0-dev+g<shortsha>`
(with exact Source HEAD shown separately), not plain `2.4.0`.
Current pinned Relay Engine (FRP): **v0.71.0**

## 1. Product definition

Data Relay Link is a lightweight secure connectivity gateway for isolated and restricted networks.

> **Secure Connectivity for Isolated Networks**

Core principle:

> **Do not connect entire networks. Relay only the connections that are actually needed.**

Product planes:

```text
Remote Access     outside → approved internal Remote Service
Internet Access   managed/protected source → approved outside destination
AI Access         authenticated AI Identity → approved target permissions
```

## 2. Product family

```text
Data Relay
├── Data Relay Control
│   Control what data moves.
└── Data Relay Link
    Control what can connect.
```

This document covers Data Relay Link only.

## 3. v2.4 public foundation

The active v2.4 public model is frozen by the CLI/AI Master.

```text
Managed Host / DRLink Agent

Network Object / Network Group
Service Object / Service Group
Permission Object / Permission Group

AI Identity
Remote Service

Remote Access
Internet Access
AI Access

BLACKLIST / WHITELIST

ConfigurationBundle
```

The earlier intermediate model based on neutral generic Objects, Managed Endpoint, Published Service, Service Preset, ordered first-match ALLOW/DENY Rules, and AI Principal is superseded.

Implementation storage or internal helper names must not redefine the public model.

## 4. Canonical product identity

```text
Product         Data Relay Link
CLI             drlink
Prompt          drlink>
Config          /etc/drlink/
State           /var/lib/drlink/
Upstream relay  official fatedier/frp
```

FRP is an internal/upstream relay-engine dependency, not the product identity.

Product version and Relay Engine version are independent.

## 5. Target scale

```text
1–5 hosts       extremely simple
10–30 hosts     comfortable CLI operation
30–50 hosts     reusable Objects/Groups are sufficient
100–1000 hosts  not the current product target
```

Do not turn Data Relay Link into a large fleet-management or network-overlay platform merely to match competitor feature lists.

## 6. CLI execution contexts

### Server

The DRLink Server manages:

```text
Managed Hosts
Enrollments
Network Objects / Groups
Service Objects / Groups
Permission Objects / Groups
AI Identities
Remote Access
Internet Access
AI Access
AI Access Log
Server ConfigurationBundle
revision/audit/backup/restore/system operations
```

### Agent Host

The Agent Host manages:

```text
Agent lifecycle
Remote Services owned by this Agent
Agent ConfigurationBundle
local diagnostics
```

Remote Service mutation is local to the Agent Host. Server inspection is read-only for Remote Service configuration. Live Agent↔Server catalog synchronization and endpoint allocation are authenticated with the enrolled Agent management identity.

## 7. Managed Host and Agent

A Managed Host is a real host managed through DRLink.

A DRLink Agent is the software installed on that Managed Host.

A Managed Host is usable as a Network Object selector where the policy context allows it, but Managed Host lifecycle remains under Managed Host commands.

## 8. Network Objects

Normal user-created Network Object types:

```text
IP
CIDR
FQDN
```

Registered Managed Hosts also appear as Network Objects of type `Managed Host`.

Network Groups are flat reusable collections.

Internet Access source may use a Managed Host.

Internet Access destination must not use a Managed Host, directly or through a Network Group containing one.

## 9. Service Objects

Service Object types (schema):

```text
TCP
UDP
Fixed TCP
```

The normal public Service Object Wizard presents operator-facing presets:

```text
SSH, HTTP, HTTPS, RDP, Custom TCP, Fixed TCP
```

UDP is not offered in that Wizard. Remote Service remains TCP / Fixed TCP only.

Internet Access v2.4 uses a TCP/HTTP/HTTPS CONNECT datapath only. UDP Service
Objects (and Service Groups containing UDP) cannot be selected by Internet Access
rules; mutation paths reject them fail-closed.

Service Groups are flat reusable collections.

Fixed TCP is not a separate policy hierarchy. It is a Service Object subtype.

## 10. Permission Objects

Permission Objects group DRLink AI-operation permissions such as:

```text
host-info
process-read
file-read
command-exec
file-write
file-upload
file-download
```

Permission Groups collect Permission Objects.

## 11. Remote Service

Remote Service represents real connectivity and is owned by an Agent Host.

```text
Agent Host
+ single destination
+ one Service Object
→ Remote Service
→ stable DRLink endpoint
```

Remote Service supports TCP and Fixed TCP Service Objects. UDP Remote Service is not supported.

When destination is another host, the current Agent Host is the Relay Host.

A policy Rule never creates connectivity.

## 12. Remote Service state and endpoint stability

States:

```text
HEALTHY
DEGRADED
DISABLED
```

Valid configuration plus temporary reachability/runtime failure results in `DEGRADED`, not deletion or configuration failure.

Endpoint reservation remains stable across:

```text
Agent restart
temporary disconnect
disable/enable
same pool-class edit
```

New valid Remote Service created while the Server is unavailable may remain `DEGRADED / Pending allocation` until reconnect.

Offline deletion synchronizes endpoint release after reconnect.

## 13. Fixed TCP

Fixed TCP Service Object defines the destination TCP service port.

When a Remote Service uses Fixed TCP, DRLink allocates the public endpoint from a separate Fixed TCP endpoint pool.

The operator does not choose the external port.

Normal TCP and Fixed TCP pool classes do not overlap, and an existing Remote Service cannot be edited in place across those classes.

## 14. Access Policy model

Three policy families:

```text
Remote Access
Internet Access
AI Access
```

Each has:

```text
Mode        BLACKLIST | WHITELIST
Enforcement ENABLED | DISABLED
Rules
```

Initial state:

```text
No Policy
No Rules
Effective access = ALLOW
```

BLACKLIST:

```text
enabled Rule match → DENY
no match           → ALLOW
```

WHITELIST:

```text
enabled Rule match → ALLOW
no match           → DENY
```

There is no rule ordering and no per-rule ALLOW/DENY action.

Deleting the last Rule preserves Mode. Policy Reset removes Mode and Rules and restores initial ALLOW.

Disabling enforcement preserves Mode/Rules but makes policy effective ALLOW ALL. AI authentication remains mandatory.

## 15. AI Identity and AI Access

AI Access source is a verified AI Identity.

Interactive AI:

```text
OAuth Authorization Code
→ verification
→ binding
→ VERIFIED
```

Automation / Custom AI:

```text
OAuth Client Credentials
→ verification
→ binding
→ VERIFIED
```

A display name alone is never authentication.

Authentication and AI Access authorization are separate.

If an MCP or other remote automation adapter is part of a qualified build, it is an integration layer over this identity and permission model; it does not introduce a separate public `AI Principal` model.

## 16. Human, AI, and ConfigurationBundle convergence

Three configuration input styles share the same semantics:

```text
Human Guided Wizard
AI complete one-shot CLI
ConfigurationBundle
```

All converge on one Change Plan.

Human Wizard draft/inline Objects remain non-authoritative until final Apply. Cancel leaves no partial state.

AI one-shot commands for a new resource must be complete. Missing dependencies are not silently created.

## 17. ConfigurationBundle

Use one-shot CLI for one independent resource.

Use ConfigurationBundle for multiple dependent resources.

Atomicity is local to the current CLI context:

```text
Server Bundle
Agent Bundle
```

There is no single distributed Server+multi-Agent transaction.

Bundle omission means unchanged. `state: absent` means explicit deletion/reset. Same desired state means `NO CHANGE`.

## 18. Runtime apply safety

Mutation pipeline:

```text
parse
validate
resolve
Change Plan
diff/security impact
confirmation
candidate authoritative transaction
runtime generation
activation
verification
success
```

Critical activation failure restores prior authoritative and runtime state where possible.

If restoration itself fails, output must truthfully report incomplete rollback and operator attention required.

A valid but unreachable Remote Service is a `DEGRADED` operational state and is not treated as critical configuration failure.

## 19. Reference protection

Referenced:

```text
Network Objects / Groups
Managed Hosts
Service Objects / Groups
Permission Objects / Groups
AI Identities
```

cannot be deleted while references remain.

The CLI lists references and applies no change.

## 20. Internet Access security boundary

Internet Access must never become an open proxy.

Required controls include:

- explicit source/destination/service authorization;
- FQDN normalization and safe DNS handling;
- DNS rebinding resistance;
- SSRF/private/local/metadata destination protection;
- validated exact-IP connection after resolution where applicable;
- safe protocol/port validation;
- fail-closed malformed security state;
- bounded resource/time-out behavior;
- safe audit logs.

These transport/security controls are independent of the BLACKLIST/WHITELIST rule semantics.

## 21. Network responsibility boundary

Data Relay Link does not silently mutate external cloud security groups, customer firewalls, NAT/DNAT, DNS providers, SSH accounts, routes, or application certificates unless a separately approved product feature explicitly says so.

## 22. Backup and restore

Backup/restore must preserve all persistent product state required for recovery, including identity, Objects/Groups, policy, Remote Service reservation/inventory state that belongs on the Server, trust material, and release provenance.

Restore uses validation and the same mutation safety principles as normal Apply.

## 23. CLI model

Server main menu:

```text
Managed Hosts
Network Objects
Service Objects
Remote Access
Internet Access
AI Access
System
Help
Exit
```

Agent Host main menu:

```text
Status
Remote Services
Agent
Configuration
Diagnostics
Help
Exit
```

Exact command grammar and Wizard/Bundle behavior are defined by the CLI/AI Master and `CLI_REFERENCE.md`.

## 24. Version and release model

The product follows `docs/VERSION_POLICY.md`.

A stable version exists only after qualification of an immutable exact HEAD and creation/publication of the corresponding immutable release artifacts.

The CLI/AI Master does not by itself change release-channel or MCP packaging decisions; those remain governed by the version/release documents and actual qualified build content.

## 25. Testing strategy

Minimum layers:

```text
static/unit
targeted regression
CLI/PTY
integration
Agent lifecycle
offline/reconnect
runtime activation/rollback
real public CLI scenarios
multi-host Real E2E
double full Real E2E on the same exact HEAD before stable
```

Critical v2.4 CLI/AI acceptance includes:

- Guided Wizard implementation and Cancel atomicity;
- BLACKLIST/WHITELIST behavior;
- Managed Host selector validation;
- Agent-local Remote Service ownership;
- Relay DEGRADED/reconnect behavior;
- Fixed TCP separate pool;
- UDP rejection;
- AI Identity verification;
- Server/Agent Bundle parity;
- runtime rollback and truthful rollback-failure path;
- role-aware help/error discovery.

## 26. Non-goals

Data Relay Link is not:

```text
VPN
full network overlay
SASE/SWG
DLP platform
large fleet orchestrator
Web-UI-first control plane
generic open proxy
transparent full-network bridge
```

## 26.1 Operator documentation set

The repository maintains task-oriented operator guides derived from the canonical specifications:

```text
DOCUMENTATION_INDEX.md
INSTALLATION.md
UPGRADE.md
REMOTE_ACCESS.md
AI_ACCESS_MCP.md
TROUBLESHOOTING.md
```

These guides make existing normative behavior easier to find. They do not override the Product Master, CLI/AI Master, Version Policy, Security specification, or exact release qualification evidence.

## 27. Documentation ownership

```text
DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md
  authoritative CLI/AI public behavior

Data Relay Link CLI Information Architecture.md
  derived menus/discovery/UX

CLI_REFERENCE.md
  derived direct command reference

CONFIGURATION_BUNDLE.md
  derived Bundle contract

CONTROL_PLANE_ARCHITECTURE.md
  internal architecture/schema history; public semantics must remain consistent with the Master

VERSION_POLICY.md / RELEASE_CHECKLIST.md / RELEASE_VALIDATION.md
  version and qualification governance
```

No other document may redefine the public CLI/AI model independently.

## 28. Decision log

### 2026-09 — Final v2.4 CLI/AI model freeze

**Decision:** Adopt the Managed Host + Network/Service/Permission Object + AI Identity + Agent-local Remote Service + BLACKLIST/WHITELIST model as the v2.4 public CLI/AI contract.

**Supersedes:** the intermediate Managed Endpoint / Published Service / Service Preset / ordered first-match ALLOW-DENY / AI Principal public model.

### 2026-09 — Fixed TCP

**Decision:** Fixed TCP is a Service Object subtype. External endpoint allocation occurs when a Remote Service uses it, from a separate Fixed TCP endpoint pool.

### 2026-09 — Context-local Bundle atomicity

**Decision:** ConfigurationBundle atomicity is scoped to the current Server or Agent CLI context, not distributed across contexts.

## 29. Master rule

Before adding a feature, ask:

> Does this make Data Relay Link better at safely and simply connecting only the services or destinations that are actually needed?

Then preserve:

> **Simple to deploy. Simple to understand. Safe to operate. Lightweight by design.**
