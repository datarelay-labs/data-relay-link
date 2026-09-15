# Data Relay Link — Canonical CLI Information Architecture

> **Document role:** Canonical CLI UX / Information Architecture Specification  
> **Product:** Data Relay Link  
> **Primary CLI:** `drlink`  
> **Status:** Normative / Living Document  
> **Applies to:** Data Relay Link v2.4.0 and later unless explicitly superseded  
> **Related documents:** `PRODUCT_MASTER.md`, `CLI_REFERENCE.md`

---

# 1. Purpose

This document defines the canonical user experience and information architecture for the Data Relay Link command-line interface.

It answers the following questions:

- What should a first-time user see after running `sudo drlink`?
- How should commands and features be grouped?
- Which terminology is user-facing?
- How should server, client, and dual-role hosts differ?
- How should direct commands differ from guided navigation?
- How should `?`, `help`, Tab completion, and menus behave?
- Which implementation terms must remain hidden?
- How should Zero-Touch onboarding be presented?
- How should CLI evolution avoid returning to a flat or implementation-oriented design?

This document is the canonical source for CLI UX and navigation decisions.

Implementation details may change, but the concepts and user-facing structure defined here must not change without an explicit product UX decision.

---

# 1.1 Final public root contract (v2.4.0)

Server / dual-role public roots are exactly:

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

Client-only roots are exactly:

```text
show
set
unset
system
menu
help
exit
```

Mental model:

```text
show   = see current state
set    = create / add / configure / modify / enable desired state
unset  = remove / delete / revoke / release / disable desired state
test   = evaluate without changing state
system = low-frequency system/maintenance operations
```

There are no other public root commands.

---

# 2. CLI Design Goals

The Data Relay Link CLI is designed for environments with approximately:

```text
1–50 clients
```

with the primary focus on a few to a few dozen systems.

The CLI must therefore optimize for:

```text
easy discovery
low learning cost
clear terminology
safe operation
fast expert usage
minimal documentation dependency
```

The product is intentionally not designed as a large-scale enterprise fleet orchestration system.

The CLI should feel understandable to an operator who has never read the documentation.

---

# 3. Two User Interfaces, One CLI

Data Relay Link intentionally provides two different CLI interaction models.

They serve different users and must not be forced into the same structure.

## 3.1 Direct command interface

Experienced users and automation use the final public grammar:

```text
show | set | unset | test | system | menu | help | exit
```

Examples:

```text
show status
show clients
show client <ID>
show services

set client
set enrollment

set client <ID> label production

add client <ID> group <GROUP>

revoke enrollment <ID>
revoke client <ID>

release service <CLIENT> <SERVICE>
release client <ID>

system update product
system diagnostics
```

The direct interface prioritizes:

```text
speed
scriptability
predictable grammar
Tab completion
```

## 3.2 Guided interactive interface

A new or occasional user should not need to learn the command grammar first.

Interactive navigation is therefore organized by **what the user wants to manage**, not by parser verbs.

The canonical server navigation is:

```text
Clients
Services
Internet Access
System
```

This distinction is fundamental:

```text
COMMANDS
=
canonical scriptable grammar

NAVIGATION
=
human task-oriented information architecture
```

The direct command tree and the guided menu must share capabilities but do not need to have the same shape.

---

# 4. Canonical Mental Model

A user should only need to understand four concepts.

```text
Clients
=
Which machines are connected?

Services
=
What services are published and who may reach them?

Internet Access
=
Where may protected/client networks connect outbound?

System
=
How is Data Relay Link itself operated?
```

Everything else belongs underneath these concepts.

---

# 5. Canonical Server Root Navigation

Running:

```bash
sudo drlink
```

on a Data Relay Link server should expose the following primary navigation:

```text
Data Relay Link
===============

1) Clients
   Connect and manage client machines

2) Services
   View published services and control who can reach them

3) Internet Access
   Allow clients to reach approved Internet destinations

4) System
   Status, settings, backup, updates and diagnostics

5) Help

6) Exit
```

These labels are canonical.

The following terms must not be used as primary root navigation categories:

```text
Remote Access
Controlled Egress
Organize
Operate
Inventory
Lifecycle
Policy
Resources
Management
```

Some of those terms remain valid architecture or implementation terminology, but they are not the first concepts a user should have to understand.

---

# 6. Product Terminology vs Navigation Terminology

Data Relay Link architecture still has two major product capabilities:

```text
Secure Remote Access
Controlled Egress
```

These remain valid product and technical terms.

However, interactive navigation uses more immediately understandable language.

```text
Secure Remote Access
→ represented through Clients + Services

Controlled Egress
→ presented to users as Internet Access
```

This prevents ambiguous menu labels such as `Remote Access`, which may sound like an action that immediately starts a remote session.

---

# 7. User-Facing Terminology Contract

The following terminology is canonical for menus and normal user-facing output.

## Clients

Machines connected to Data Relay Link.

Examples:

```text
Linux server
Windows workstation
macOS machine
GPU server
Mac Studio
```

## Services

Services published from clients through Data Relay Link.

Examples:

```text
SSH
HTTP
HTTPS
RDP
Custom TCP
```

## Groups

Collections of clients for easier organization.

Groups belong under:

```text
Clients
```

## Service Profiles

Reusable templates for creating services.

Service Profiles belong under:

```text
Services
```

## Access Rules

Rules controlling which source IP addresses may connect to published services.

The implementation/direct-command object may continue to use:

```text
access-list
```

but beginner-facing navigation uses:

```text
Access Rules
```

## Internet Access

Approved outbound connectivity from protected/client networks to Internet destinations.

This is the user-facing navigation term for:

```text
Controlled Egress
```

## Access Profiles

Internet Access policy profiles.

The backend/direct-command resource may continue to use:

```text
egress-profile
```

## Fixed TCP

Outbound TCP access for applications that cannot use HTTP/HTTPS proxy semantics.

## Templates

Predefined starting configurations for Internet Access.

Backend implementation may continue to call these:

```text
egress recipes
```

but the normal guided UI uses:

```text
Templates
```

## Diagnostics

Health and troubleshooting functions.

The direct command remains:

```text
system diagnostics
```

## Relay Engine (FRP)

When the upstream FRP component must be exposed to the user, prefer:

```text
Relay Engine (FRP)
```

FRP is the implementation/upstream relay engine, not the Data Relay Link product identity.

---

# 8. Clients Navigation

Canonical server submenu:

```text
Clients
=======

1) Connect a new client
2) List clients
3) View or manage a client
4) Groups
5) Enrollments
6) Back
```

---

# 9. Connect a New Client

The normal onboarding task is:

```text
Connect a new client
```

A first-time operator should not need to understand:

```text
Zero-Touch
Bootstrap ticket
Enrollment internals
```

before connecting a machine.

The guided workflow internally maps to:

```text
set client
```

but the user-facing task remains:

```text
Connect a new client
```

---

# 10. Zero-Touch Onboarding Flow

The canonical high-level flow is:

```text
Connect a new client
        ↓
Select platform
        ↓
Client details
        ↓
Configure service(s)
        ↓
Review
        ↓
Generate Zero-Touch command
```

## 10.1 Platform

```text
Platform
========

1) Linux
2) Windows
3) Back
```

## 10.2 Client details

Collected exactly once:

```text
Client details
==============

Client name:
Description [optional]:
```

`Description` is optional.

Leaving it blank must not trigger another identification prompt later in the workflow.

The same `Client identification` step must never appear twice during one onboarding flow.

---

# 11. Linux Service Setup

Canonical Linux onboarding choices:

```text
How do you want to configure this client?

1) SSH only
2) Choose services
3) Back
```

The following option must not be offered during new onboarding:

```text
Connect this machine only
(management-only; no published services)
```

New onboarding requires at least one useful service.

---

# 12. Windows Service Setup

Canonical Windows onboarding choices:

```text
How do you want to configure this client?

1) RDP only
2) SSH only
3) Choose services
4) Back
```

Windows bootstrap security requirements remain unchanged.

The secure flow remains:

```text
download PowerShell bootstrap
        ↓
verify expected SHA256
        ↓
execute verified file
```

Shorter commands must never weaken hash-before-execute behavior.

---

# 13. Management-Only State

There is an important difference between:

```text
NEW onboarding with zero services
```

and:

```text
an EXISTING enrolled client with zero remaining services
```

The canonical contract is:

```text
INITIAL_ONBOARDING_REQUIRES_AT_LEAST_ONE_SERVICE=YES

MANAGEMENT_ONLY_INITIAL_ONBOARDING_OPTION=NO

EXISTING_CLIENT_MAY_HAVE_ZERO_SERVICES=YES
```

For example:

```text
client has SSH service
        ↓
operator releases SSH reservation
        ↓
client remains enrolled
        ↓
client now has zero published services
```

This is valid.

Therefore removal of the management-only onboarding option must not break existing zero-service lifecycle states.

---

# 14. View or Manage a Client

After a client is selected, the CLI should preserve that selection as context.

Example:

```text
Client: 24cd7856
Label : production

1) Overview
2) Services
3) Details and tags
4) Groups
5) Revoke management trust
6) Remove client from server
7) Back
```

The CLI should not repeatedly ask the operator to enter the same CLIENT ID.

Mappings:

```text
Overview
→ show client <ID>

Services
→ show client <ID> services

Details and tags
→ show / set / unset client metadata

Groups
→ group membership operations

Revoke management trust
→ revoke client <ID>

Remove client from server
→ release client <ID>
```

---

# 15. Revoke vs Release

These operations must remain distinct.

## Revoke client

```text
revoke client <ID>
```

Blocks the client's management trust.

It does not release all reservations.

## Release service

```text
release service <CLIENT> <SERVICE>
```

Releases one service reservation.

The client remains enrolled.

## Release client

```text
release client <ID>
```

Removes:

```text
client registry record
management identity
all service reservations
all public ports
```

It does not:

```text
delete the remote machine
uninstall Data Relay Link on the remote machine
```

Guided confirmations must explain these effects clearly.

---

# 16. Groups

Groups belong under:

```text
Clients
```

Canonical submenu:

```text
Groups
======

1) List groups
2) Create group
3) View or manage a group
4) Back
```

Selected group:

```text
Group: <NAME>

1) Overview
2) Rename / description
3) View members
4) Add client
5) Remove client
6) Delete group
7) Back
```

Do not create a separate `Organize` root merely for Groups and Profiles.

Place concepts near the objects they organize.

---

# 17. Enrollments

Enrollments are an advanced onboarding/lifecycle function under:

```text
Clients
```

Canonical submenu:

```text
Enrollments
===========

Manual codes and recent/pending client enrollments.

1) List enrollments
2) Create manual enrollment code
3) Create enrollment codes in bulk
4) Revoke active enrollment
5) Delete terminal enrollment record
6) Back
```

Canonical direct commands:

```text
show enrollments
set enrollment
set enrollments
revoke enrollment <ID>
delete enrollment <ID>
```

Normal Zero-Touch onboarding should remain under:

```text
Clients
→ Connect a new client
```

---

# 18. Services Navigation

Canonical server submenu:

```text
Services
========

Published services and inbound access control.

1) List published services
2) View a client's services
3) Access Rules
4) Service Profiles
5) Release a service reservation
6) Back
```

The server must not pretend to remotely edit local service definitions if that capability does not exist.

Where appropriate, display:

```text
Service definitions are changed on the client.
Use drlink on that client to add or edit services.
```

Do not invent remote mutation behavior for UX convenience.

---

# 19. Access Rules

Access Rules belong under:

```text
Services
```

because they control access to published services.

Canonical submenu:

```text
Access Rules
============

Control which source IPs may reach published services.

1) List rules
2) Create rule
3) View or edit rule
4) Assign rule to a service
5) Set service to public access
6) Check access for a source IP
7) Recent access decisions
8) Back
```

Selected rule:

```text
Access Rule: <NAME>

1) Overview
2) Name / description
3) Allowed sources
4) Remove expired sources
5) Delete rule
6) Back
```

Security behavior is not changed by this terminology.

---

# 20. Service Profiles

Service Profiles belong under:

```text
Services
```

Canonical submenu:

```text
Service Profiles
================

Reusable templates for creating services.

1) List profiles
2) Create profile
3) View or edit profile
4) Delete profile
5) Back
```

Profiles are templates.

They must not imply ownership of:

```text
public ports
client identity
access assignments
existing services
```

unless existing product behavior explicitly provides it.

---

# 21. Internet Access

Canonical root:

```text
Internet Access
```

Description:

```text
Allow clients to reach approved Internet destinations.
Everything else remains denied by default.
```

Canonical submenu:

```text
Internet Access
===============

1) Overview
2) Access Profiles
3) Fixed TCP
4) Templates
5) Check policy
6) Back
```

This is the guided UI for the Controlled Egress capability.

---

# 22. Internet Access — Security Model

Changing the menu name from Controlled Egress to Internet Access must not change its security semantics.

The existing security model remains authoritative:

```text
default DENY
explicit approved destinations
explicit protocol
approved sources
FQDN validation
DNS rebinding protection
no implicit allow
```

UI simplification must never weaken policy enforcement.

---

# 23. Access Profiles

Canonical submenu:

```text
Access Profiles
===============

1) List profiles
2) Create profile
3) View or manage profile
4) Import profile
5) Compare with import file
6) Back
```

Selected profile:

```text
Profile: <NAME>

1) Overview
2) Name / description
3) Allowed sources
4) Allowed destinations
5) Check policy
6) Enable / Disable
7) Export
8) Delete profile
9) Back
```

New profiles remain disabled until explicitly enabled.

---

# 24. Fixed TCP

Canonical label:

```text
Fixed TCP
```

Description:

```text
Outbound TCP access for applications that cannot use an HTTP/HTTPS proxy.
```

Canonical submenu:

```text
Fixed TCP
=========

1) List Fixed TCP entries
2) Create Fixed TCP entry
3) View or manage an entry
4) Back
```

Selected entry:

```text
Fixed TCP: <NAME>

1) Overview
2) Check source authorization
3) Enable
4) Disable
5) Delete
6) Back
```

The underlying direct/backend resource may continue to use `egress-tcp`.

---

# 25. Templates

The guided UI uses:

```text
Templates
```

instead of the implementation-oriented term:

```text
Recipes
```

Canonical submenu:

```text
Templates
=========

Predefined starting points for Internet Access configuration.

1) List templates
2) View template
3) Create configuration from template
4) Back
```

Backend implementation may continue using `egress-recipe`.

---

# 26. Check Policy

The Controlled Egress `explain` operation evaluates:

```text
policy
+
DNS
```

It does not necessarily establish a live connection to the final destination.

Therefore the guided UI should use:

```text
Check policy
```

or:

```text
Check whether this access would be allowed
```

It must not misleadingly call this:

```text
Test connection
```

unless an actual live connectivity test is performed.

---

# 27. System Navigation

Canonical:

```text
System
======

1) Status
2) Server Settings
3) Backup & Restore
4) Updates
5) Diagnostics
6) Audit Log
7) Version Information
8) Back
```

`System` is intentionally used instead of the more abstract `Operate`.

---

# 28. Server Settings

Canonical submenu:

```text
Server Settings
===============

1) Published service hostname
2) Bootstrap hostname
3) Client installer URL
4) Back
```

Existing technical semantics remain unchanged.

In particular:

```text
public_ip / public_host
=
control / allocator identity

public_hostname
=
optional published-service access alias

bootstrap_hostname
=
optional Zero-Touch bootstrap hostname
```

Changing `public_hostname` must not silently change allocator/control identity.

---

# 29. Backup & Restore

Canonical:

```text
Backup & Restore
================

1) Create backup
2) Restore backup
3) Back
```

Existing backup validation, rollback, and restore safety behavior must be retained.

---

# 30. Updates

Canonical:

```text
Updates
=======

1) Update Data Relay Link
2) Check upstream relay-engine release
3) Update Relay Engine (FRP)
4) Back
```

FRP remains visible only where distinguishing the upstream engine from the Data Relay Link product is useful.

---

# 31. Diagnostics

Canonical:

```text
Diagnostics
===========

1) Run health checks
2) Create support bundle
3) Back
```

Direct mappings:

```text
Run health checks
→ system diagnostics

Create support bundle
→ system support-bundle
```

The direct command `system diagnostics` remains valid and canonical.

---

# 32. Client-Only Host Navigation

A host installed only as a client must not show server-only concepts.

Canonical root:

```text
Data Relay Link
===============

1) Services
   Configure services published from this machine

2) System
   Status, connection information, updates and diagnostics

3) Help

4) Exit
```

---

# 33. Client Services

Canonical client-only submenu:

```text
Services
========

1) List services
2) Add service
3) Edit service
4) Enable service
5) Disable service
6) Apply pending changes
7) Discard pending changes
8) Sync with server
9) Back
```

Direct mappings include:

```text
show services
add service
set service
enable service
disable service
apply
discard
sync
```

---

# 34. Client System

Client System exposes existing client capabilities:

```text
Status
Connection information
Version information
Update Data Relay Link
Update Relay Engine (FRP)
Diagnostics
Support Bundle
Back
```

Direct commands include:

```text
show status
show info
show version
system update product
system update engine
system diagnostics
system support-bundle
```

---

# 35. Dual-Role Hosts

A host acting as both server and client should not expose:

```text
Client operations
Server operations
```

as its primary navigation.

Use the normal server product-domain model:

```text
Clients
Services
Internet Access
System
Help
Exit
```

Inside Services, distinguish where necessary between:

```text
Published services
Local services on this machine
```

The user should think in product concepts rather than implementation roles.

---

# 36. Root `?`

Bare:

```text
?
```

must not be a dump of parser verbs.

This is NOT acceptable as the primary discovery experience:

```text
show
create
set
unset
add
remove
enable
disable
revoke
release
delete
restore
update
test
system diagnostics
...
```

Instead, root `?` should explain the product domains.

Example:

```text
Data Relay Link
===============

Commands

  Clients
    Connect and manage client machines

  Services
    View published services and control who can reach them

  Internet Access
    Allow clients to reach approved Internet destinations

  System
    Status, settings, backup, updates and diagnostics

Guided navigation:
  menu

Quick commands:
  show status
  show clients
  show services
  set client
  system diagnostics

Help:
  help clients
  help services
  help internet
  help system
  help commands
```

Output must be role-aware.

---

# 37. Help Architecture

Required topics:

```text
help
help clients
help services
help internet
help system
help workflows
help commands
help legacy
```

## `help`

Product/domain overview.

## `help clients`

Client onboarding, inventory, groups, enrollment, lifecycle.

## `help services`

Published services, Access Rules, Service Profiles.

## `help internet`

Internet Access / Controlled Egress concepts and workflows.

## `help system`

Status, settings, backups, updates, diagnostics.

## `help workflows`

Common end-to-end tasks.

## `help commands`

Complete advanced canonical command reference.

## `help legacy`

Hidden compatibility grammar.

---

# 38. `help commands`

The complete direct command grammar belongs under:

```text
help commands
```

Every non-hidden public canonical command must be:

```text
parseable
Tab-discoverable
documented in help commands
```

Advanced actions such as:

```text
explain
export
import
diff
apply
```

where public and valid must not disappear merely because they are not shown in root navigation.

Progressive disclosure is preferred over capability removal.

---

# 39. Tab Completion

Tab completion remains part of the expert direct-command interface.

It must be:

```text
safe
non-executing
deterministic
context-aware
role-aware
```

Tab must never execute commands or mutate state.

---

# 40. Grouped Completion Display

Large completion/context lists should be visually grouped by user domain where practical.

Example for:

```text
show ?
```

Conceptually:

```text
Clients
  clients
  client
  groups
  group
  enrollments
  enrollment

Services
  services
  service-profiles
  service-profile
  access-lists
  access-list
  access-service
  access-log

Internet Access
  egress
  egress-profiles
  egress-profile
  egress-tcp
  egress-tcp-entry
  egress-recipes
  egress-recipe

System
  status
  version
  server-status
  upstream
  audit
```

The grouping affects display only.

It must not change parser semantics.

---

# 41. Navigation Tree vs Command Catalog

The implementation must maintain two distinct concepts.

```text
COMMANDS
```

is the single source of truth for the direct command grammar.

```text
NAVIGATION_TREE
```

is the single source of truth for guided navigation.

Every guided-menu leaf must map to either:

```text
a canonical drlink command
```

or:

```text
an explicitly defined canonical guided workflow
```

A guided menu should not bypass the public `drlink` layer and invoke internal backend tools directly when a canonical operation exists.

---

# 42. Menu Presentation

Normal menus should show user tasks, not parser implementation.

Bad:

```text
Clients (show clients / show client / set client)
```

Good:

```text
1) Clients
   Connect and manage client machines
```

Detailed direct syntax belongs under:

```text
help commands
```

or contextual help.

---

# 43. Navigation Depth

Normal menu depth should remain shallow.

Preferred:

```text
Root
→ Domain
→ Object/list
→ Selected object actions
```

Avoid deeply nested enterprise-style navigation.

After an object is selected, preserve it as context.

Examples:

```text
Client: 24cd7856
Group: production
Access Rule: office
Profile: ubuntu-updates
Fixed TCP: vendor-license
```

The user should not have to re-enter the same identifier for every operation.

---

# 44. Back, Cancel, and Exit

Canonical behavior:

```text
Back
→ one navigation level up

Cancel
→ leave the current operation without mutation

Exit
→ leave the Data Relay Link CLI
```

A cancelled guided flow must not partially modify configuration.

---

# 45. Shell vs REPL Command Guidance

Output must know whether the operator is already inside:

```text
drlink>
```

## Inside REPL

Use:

```text
show enrollments
revoke enrollment <ID>
delete enrollment <ID>
```

Never instruct the user to type another leading:

```text
drlink
```

inside the REPL.

## Shell-facing output

Use:

```text
sudo drlink show enrollments
sudo drlink revoke enrollment <ID>
sudo drlink delete enrollment <ID>
```

The distinction must be consistent across all generated guidance.

---

# 46. Enrollment Vocabulary

Current canonical actions are:

```text
show enrollments
revoke enrollment <ID>
delete enrollment <ID>
```

Do not advertise older forms such as:

```text
drlink enrollment list
drlink enrollment revoke <ID>
purge enrollment <ID>
```

`purge` may remain internally or as hidden compatibility behavior if required, but it is not current public vocabulary.

---

# 47. Backend Isolation

Normal operator output must not expose implementation commands such as:

```text
frp-create-client
frp-client
frp-access
frp-egress
frp-profile
frp-groups
frpctl
```

Internal implementation may continue using these components.

The public product interface is:

```text
drlink
```

---

# 48. GNU-Style Options

Normal interactive UX should not require users to understand internal GNU-style options such as:

```text
--ttl
--ssh
--force
--protocol
--yes
```

Complex normal operations should use guided prompts.

Internal automation and compatibility paths may continue to use flags where necessary.

Normal:

```text
?
help
menu
Tab
examples
```

must not unnecessarily expose them.

---

# 49. Safety and Confirmation

Destructive or security-sensitive operations must remain explicit.

Examples include:

```text
revoke client
release client
release service
delete access rule
delete Internet Access profile
system restore
widen public access
```

Confirmation text should explain effects in user terms rather than internal implementation terms.

---

# 50. Discovery Consistency

The following surfaces must use consistent terminology:

```text
?
help
menu
Tab candidate display
error messages
Zero-Touch output
completion screens
documentation
```

A feature must not be called:

```text
Access Rule
```

in one menu,

```text
Access Rule
```

in another,

and:

```text
ACL object
```

in a third unless the context explicitly requires the technical distinction.

---

# 51. Product UX Invariants

The following are canonical invariants.

```text
CLI_DIRECT_GRAMMAR=ACTION_FIRST

SERVER_ROOT=
Clients
Services
Internet Access
System
Help
Exit

CLIENT_ROOT=
Services
System
Help
Exit

ROOT_NAVIGATION_IS_NOT_ACTION_LIST=YES

BACKEND_TOOLS_USER_VISIBLE=NO

MANAGEMENT_ONLY_INITIAL_ONBOARDING=NO

INITIAL_ONBOARDING_REQUIRES_SERVICE=YES

EXISTING_ZERO_SERVICE_CLIENT_VALID=YES

CLIENT_IDENTIFICATION_COLLECTED_ONCE=YES

DESCRIPTION_OPTIONAL=YES

PUBLIC_ENROLLMENT_DELETE_TERM=delete

CONTROLLED_EGRESS_BEGINNER_TERM=Internet Access

GROUPS_PARENT=Clients

SERVICE_PROFILES_PARENT=Services

ACCESS_RULES_PARENT=Services
```

---

# 52. Non-Goals

The CLI IA must not be used as justification for expanding the product into:

```text
Web UI
enterprise fleet manager
hundreds/thousands of clients orchestration
database-backed management platform
HA management cluster
policy orchestration platform
generic VPN
generic SOCKS proxy
TLS inspection
DLP
```

The CLI remains optimized for lightweight operation of approximately 1–50 clients.

---

# 53. Implementation Rule

When implementation and this specification disagree:

1. Verify whether this document reflects the latest explicit product UX decision.
2. If yes, implementation should be brought into alignment.
3. Do not silently reinterpret the navigation structure based on backend object names.
4. Do not flatten the guided interface merely because the command parser is canonical.

The parser and navigation solve different problems.

---

# 54. Documentation Rule

`PRODUCT_MASTER.md` should contain a concise normative summary of this architecture and reference this document.

`CLI_REFERENCE.md` should document:

```text
actual canonical direct syntax
```

and should not redefine the navigation architecture independently.

This document owns:

```text
terminology
information architecture
guided navigation
discovery UX
```

---

# 55. Testing Contract

CLI regression tests should protect at least:

```text
server root domains
client root domains
role filtering
guided navigation hierarchy
root ? domain orientation
help topics
complete help commands parity
Tab safety
grouped candidate display
Zero-Touch onboarding flow
single client-identification prompt
blank optional description
no management-only initial onboarding
existing zero-service lifecycle
REPL vs shell command hints
no backend command leakage
no public stale resource-first syntax
```

Tests should validate product UX contracts rather than exact incidental spacing wherever possible.

---

# 56. Final UX Principle

The Data Relay Link CLI should make the correct next action obvious without requiring the operator to understand its internal architecture.

The beginner thinks:

```text
I need to connect a machine
→ Clients

I need to expose SSH or HTTP
→ Services

I need this internal machine to access an approved Internet destination
→ Internet Access

I need to check or maintain Data Relay Link itself
→ System
```

The experienced operator can skip navigation and type:

```text
show clients
set client
revoke enrollment <ID>
system diagnostics
```

Both interfaces are first-class.

The product should never force a beginner to think like the command parser, and it should never slow down an experienced operator with unnecessary menus.