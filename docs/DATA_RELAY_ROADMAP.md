# Data Relay Link Roadmap

> **Status:** Living roadmap aligned to the v2.4.0 Control Plane / Policy / MCP architecture
> **Product Master:** `PRODUCT_MASTER.md`
> **Public model:** `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`

## 1. Roadmap principle

Finish foundations that would be expensive to replace after stable release. Defer features that can be added later without changing those foundations.

Foundation to finish before v2.4.0 stable:

```text
SQLite authority
immutable Managed Host / Agent identity
Network Objects / Groups
Service Objects / Groups
Permission Objects / Groups
Managed Host address inventory
Agent-owned Remote Services
BLACKLIST / WHITELIST Remote Access policy
BLACKLIST / WHITELIST Internet Access policy
AI Identity + AI Access / MCP Bridge
revisions / audit
runtime generation
backup / migration
canonical CLI nouns
ConfigurationBundle + shared Change Plan
AI-generated canonical CLI / copy-paste bundle workflow
bounded Zero-Touch issuance (max 10/request and active unused)
```

Can remain later work:

```text
Web UI
central SaaS management
external DB / HA
large-fleet orchestration
SIEM/reporting
broad vendor destination catalogs
```

## 2. Phase DL-0 — proven relay foundation

**Status:** Existing foundation; preserve while redesigning control plane.

Includes:

```text
official fatedier/frp
Zero-Touch / Manual Enrollment
immutable Client identity
multi-service relay
public-port reservation
Linux/macOS/Windows clients
lifecycle/update/doctor/support bundle
```

Do not fork FRP.

## 3. Phase DL-1 — control-plane architecture closure

**Status:** Architecture approved; docs-first closure in progress.

Required:

```text
CONTROL_PLANE_ARCHITECTURE.md
Product Master alignment
CLI IA alignment
Security alignment
Version/release governance alignment
MCP inclusion decision aligned
```

No stable tag during this phase.

## 4. Phase DL-2 — SQLite control-plane implementation

**Status:** Next implementation phase.

Implement:

```text
/var/lib/drlink/drlink.db
schema_migrations
system_meta
config_revisions
revision_snapshots
audit_events
runtime_generations
```

Required properties:

```text
foreign keys
WAL
synchronous durability
busy timeout
trusted_schema off
transactional mutation
optimistic concurrency
integrity checks
unsupported-schema fail closed
```

## 5. Phase DL-3 — Object and endpoint model

Implement:

```text
objects
object_values
object_group_members
clients
managed_endpoints
endpoint_addresses
client_groups
client_group_members
client_tags
```

Acceptance:

```text
neutral Objects
no Source/Destination object duplication
multi-value static Objects
Object Group cycle protection
context validation
Managed Host lifecycle ownership
no silent identity rebinding
Managed Host local address inventory
reference-protected deletion
```

## 6. Phase DL-4 — Remote Service / Service Object model

Internal storage may retain compatibility table names such as `published_services` and `service_presets`, but they do not define the public model.

Acceptance:

```text
Agent Host owns Remote Service mutation
single destination + one Service Object
TCP and Fixed TCP Remote Service
UDP Remote Service rejected
Relay Host semantics for another-host destination
stable endpoint identity
policy-impact analysis on destination/Service Object changes
Service Object Wizard presets are creation conveniences, not public resources
```

## 7. Phase DL-5 — Remote Access policy

Implement the shared BLACKLIST / WHITELIST policy engine and Remote Access evaluator/compiler.

Acceptance:

```text
No Policy / No Rules = effective ALLOW
BLACKLIST match DENY / no match ALLOW
WHITELIST match ALLOW / no match DENY
rule enable/disable
no rule ordering
no per-rule ALLOW/DENY action
Policy Reset semantics
Enforcement disable/enable
impact analysis
flow test/explain
Remote Service + reachability intersection
```

Legacy ACL becomes non-canonical and is removed/hidden before stable.

## 8. Phase DL-6 — Internet Access policy

Replace legacy Internet Profile authoritative policy with Network/Service Objects plus the shared BLACKLIST / WHITELIST policy model.

Preserve/harden protocol boundary:

```text
HTTP forward proxy
HTTPS CONNECT
server-side DNS
SSRF/special-address protection
DNS rebinding resistance
CONNECT/SNI binding
controlled wildcard semantics
public Host/CIDR explicit policy
Fixed TCP through same authority
resource limits
safe audit
```

Acceptance includes curl/wget/git/apt Real E2E plus denied-traffic escape tests.

## 9. Phase DL-7 — revision/audit/runtime compiler

Implement one mutation pipeline:

```text
validate
→ impact
→ confirm
→ transaction
→ revision/audit
→ compile
→ atomic activate
→ verify generation
```

Acceptance:

```text
system audit
system revisions
runtime revision status
compiler failure surfaced
generation mismatch fail closed where required
```

Rollback may be added only if its semantics are fully transactional and qualified.

## 10. Phase DL-8 — backup / restore / migration

Implement SQLite Online Backup/equivalent consistent snapshot.

Acceptance:

```text
backup during WAL activity
config/trust/secret recovery
restore integrity + FK checks
schema compatibility
runtime regeneration
permissions/ownership
pre-upgrade backup
migration rollback/failure safety
```

Legacy JSON is migration input only, not dual authority.

## 11. Phase DL-9 — MCP Bridge / AI Access

**Status:** Included in v2.4.0 target; supersedes old exclusion decision.

Implement server-side MCP Bridge plus:

```text
AI Identity backing state
AI Access Rules
Network Object / Network Group targets
Permission Object / Permission Group references
path scopes / exec constraints
AI sessions / activity
```

Targets:

```text
Network Object
Network Group
```

Minimum capabilities:

```text
exec
read_file
write_file
upload_file
download_file
```

Additional discovery:

```text
list_hosts
get_host
get_system_info
list_processes
```

Security:

```text
current official MCP spec
modern supported remote transport
authenticated HTTPS
strong AI Identity binding
per-invocation authorization
least privilege
path scopes
exec timeout/process controls
audit
no per-host MCP server requirement
```

Real interoperability is required for each client explicitly claimed supported.

## 12. Phase DL-10 — canonical CLI implementation

Implement guided root:

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

Direct roots:

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

Remove/hide pre-stable legacy public resources:

```text
service-profile
internet-profile
legacy ACL naming
ambiguous generic group
```

Protect impact confirmation, stale edit detection, contextual Tab completion, REPL/shell hints, and backend isolation.

## 13. Phase DL-11 — release-governance transition

Remove old hard-coded v2.4 MCP exclusion from:

```text
release manifest schema
manifest generator
version identity validation
release governance scripts
version consistency checks
tests
release manifest content
```

Final candidate truth:

```text
features.mcp_included=true
```

only after actual MCP implementation exists and passes qualification.

Keep exact-SHA pretag provenance, immutable tags, source/dist parity, checksums, and historical tag immutability.

## 14. Phase DL-12 — full automated closure

Required:

```text
static validation
DB/migration tests
Object tests
policy evaluator/compiler tests
shadow/impact tests
CLI/PTy tests
Internet security tests
MCP auth/capability/path tests
backup/restore tests
release governance tests
full local suite
CI
source/dist parity
secret/public metadata scan
```

No stale test is allowed to redefine the approved architecture.

## 14.1 Phase DL-12A — ConfigurationBundle and bounded Zero-Touch

**Status:** Required before v2.4.0 stable.

Implement one shared Change Plan path for direct CLI, AI-generated commands, and declarative ConfigurationBundle input.

Required closure:

```text
file + stdin ConfigurationBundle
validate / embedded policy tests / diff
idempotent present + explicit absent semantics
one atomic transaction
revision conflict protection
policy-impact confirmation
redacted export
secret exclusion
AI copy/paste real CLI E2E
CLIENT_ACTION_REQUIRED boundary
Zero-Touch enrollment plans separate from ticket issuance
max 10 tickets per issuance request
max 10 active unused tickets
unique single-use ticket
1h default / 24h max TTL
atomic consumption / double-use denial
```

This phase must reuse the canonical SQLite/domain policy engine; do not add a second YAML/AI state engine.

## 15. Phase DL-13 — multi-host Real E2E

Matrix:

```text
Ubuntu 24
Windows 10
Rocky Linux 8
Rocky Linux 9
Amazon Linux 2023
macOS Apple Silicon
```

Validate install, enrollment, services, policy, Internet Access, lifecycle, reboot, backup/restore, and supported AI/MCP operations.

## 16. Phase DL-14 — final exact-HEAD qualification

Freeze candidate HEAD, then:

```text
FULL_REAL_E2E_PASS_1=PASS
FULL_REAL_E2E_PASS_2=PASS
PASS1_HEAD==PASS2_HEAD
```

Both passes include all three access planes and release lifecycle applicable to stable claims.

Any code/dependency/generated-artifact change resets the counter.

## 17. Phase DL-15 — stable publication

Only after all gates:

```text
create immutable v2.4.0 tag
publish immutable artifacts/checksums/manifest
publish release notes
update stable channel
update public docs
verify clean stable install/bootstrap/update
```

## 18. Post-v2.4 demand-driven work

Potential later additions only with real demand:

```text
Web UI
central multi-server/fleet coordination
enterprise identity providers beyond required MCP auth
HA deployment
reporting/SIEM exports
more protocols
more Fixed TCP presets
policy rollback UX enhancements
signed policy/export packages
```

These additions should reuse, not replace, the v2.4 identity/Object/policy/database foundation.

## 19. Stable non-goals

Data Relay Link is not being expanded into:

```text
VPN/full network overlay
SASE/SWG/CASB/DLP
TLS inspection platform
RMM/fleet orchestrator
automatic firewall/DNS manager
large database cluster
```

## 20. Roadmap success condition

The v2.4.0 foundation is done when no further foreseeable core change requires replacing:

```text
control-plane authority
identity model
Object model
BLACKLIST / WHITELIST policy semantics
Remote Service destination/Service Object semantics
AI Identity / permission authorization model
backup/migration model
canonical CLI nouns
```

Feature growth after that point should be additive.
