# Data Relay Link — Canonical CLI Information Architecture

> **Document role:** Canonical CLI UX / information architecture
> **Status:** Approved v2.4.0 target; implementation qualification pending
> **Primary CLI:** `drlink`
> **Architecture:** `CONTROL_PLANE_ARCHITECTURE.md`

## 1. Purpose

This document defines how Data Relay Link presents the v2.4.0 control-plane model to operators.

The CLI must be understandable to a first-time operator and predictable for an experienced operator. It must also make security-impacting changes explicit.

The canonical mental model is:

```text
Clients
Objects
Remote Access
Internet Access
AI Access
System
```

The old canonical model based on generic Groups, Service Profiles, Access Rules, and Internet Profiles is superseded.

## 2. Two interfaces, one semantic model

### Direct interface

Experienced operators and automation use action-first commands:

```text
drlink <ACTION> <RESOURCE> [TARGET] [PROPERTY] [VALUE]
```

Canonical direct roots:

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

### Guided interface

Interactive mode is task/domain oriented:

```text
sudo drlink
```

The menu preserves selected-object context and hides implementation terms.

Direct and guided paths must call the same validation, impact-analysis, transaction, revision, and policy compiler paths.

## 3. Server root

Canonical server root:

```text
Data Relay Link
===============

1) Clients
   Connect and manage client machines

2) Objects
   Define reusable hosts, networks and destinations

3) Remote Access
   Control inbound access to published services

4) Internet Access
   Control approved outbound Internet access

5) AI Access
   Control AI/MCP access to managed endpoints

6) System
   Status, audit, revisions, backup, updates and diagnostics

7) Help
8) Exit
```

These root labels are normative.

## 4. Client-only root

A client-only host does not expose server policy/control-plane areas:

```text
Data Relay Link
===============

1) Published Services
2) System
3) Help
4) Exit
```

Client-side Published Service definition/editing remains local unless the product explicitly implements server-driven mutation.

## 5. Dual-role host

A dual-role host uses the server root. Where necessary, Published Services distinguishes:

```text
Published services from managed clients
Local published services on this machine
```

Do not expose implementation roles as the primary root hierarchy.

## 6. Canonical terminology

| Canonical term | Meaning | Supersedes / avoids |
|---|---|---|
| Client | Enrolled Data Relay Link client | — |
| Managed Endpoint | Policy-visible managed identity for a Client | treating hostname/IP as identity |
| Client Group | Operational collection of Clients | generic `group` ambiguity |
| Object | Neutral Host/Network/FQDN/Managed Endpoint policy object | source-object / destination-object |
| Object Group | Reusable network-policy Object collection | generic group ambiguity |
| Published Service | Inbound relay definition | ambiguous `Service` |
| Service Preset | Creation-time Published Service template | Service Profile |
| Remote Access | Inbound policy plane | ACL / Access Rule as primary UX |
| Internet Access | Outbound policy plane | Internet Profile as primary UX |
| AI Principal | Authenticated AI/MCP identity | AI as Network Object |
| AI Access | AI capability policy plane | mixing MCP into Remote Access |
| Diagnostics | Health/troubleshooting | internal tool names |

`Controlled Egress` remains a technical capability description, but `Internet Access` is the normal CLI navigation/resource name.

## 7. Clients

Canonical submenu:

```text
Clients
-------

1) Connect a new client
2) List clients
3) View or manage a client
4) Client Groups
5) Enrollments
6) Back
```

### Connect a new client

Guided flow:

```text
platform
→ client name / description
→ initial Published Service(s)
→ review
→ create Zero-Touch bootstrap
```

Initial onboarding requires at least one useful Published Service unless an explicit future product decision changes that contract.

An existing client may later have zero services after releases/removals.

### Selected client

```text
Client: <LABEL>
Client ID: <ID>

1) Overview
2) Managed Endpoint
3) Published Services
4) Details and tags
5) Client Groups
6) Revoke management trust
7) Remove client from server
8) Back
```

The operator should not re-enter the Client ID for each action.

## 8. Managed Endpoint view

A selected Client exposes its policy identity and local address inventory:

```text
Managed Endpoint: dp1
Status: Connected
Client ID: facc9a57

Addresses
---------
10.10.10.10   eth0    private   active
10.10.20.1    virbr0  private   active
```

Managed Endpoint is viewable but not manually created/deleted from Object CRUD.

An Orphaned endpoint view explains why it remains referenced.

## 9. Client Groups

```text
Client Groups
=============

1) List groups
2) Create group
3) View or manage a group
4) Back
```

Selected group:

```text
Client Group: <NAME>

1) Overview
2) Rename / description
3) Members
4) Add client
5) Remove client
6) Delete group
7) Back
```

Client Group is distinct from Object Group.

## 10. Enrollments

```text
Enrollments
===========

1) List enrollments
2) Create manual enrollment
3) Create Zero-Touch enrollment
4) Revoke enrollment
5) Delete terminal record
6) Back
```

Security-sensitive tickets/secrets are not shown after their one-time issuance window unless explicitly required by a safe workflow.

## 11. Objects

Canonical submenu:

```text
Objects
-------

1) List objects
2) Create object
3) View or edit object
4) Object Groups
5) Find references
6) Back
```

Object list should distinguish static and managed origin:

```text
NAME          TYPE              SOURCE       STATUS
external1     Network           Static       -
external2     FQDN              Static       -
internal1     Network           Static       -
dp1           Managed Endpoint  Data Relay   Connected
```

## 12. Create Object

Guided static Object creation:

```text
Name
→ Type: Host | Network | FQDN
→ Value(s)
→ Description [optional]
→ Reference/policy impact preview if applicable
→ Commit
```

`Managed Endpoint` is not a user-selectable creation type.

Object values are validated and normalized before commit.

## 13. Selected Object

```text
Object: external2
Type: FQDN

1) Overview
2) Values
3) Name / description
4) References
5) Delete
6) Back
```

Adding/removing values runs policy-impact analysis before commit.

If access broadens, interactive confirmation is default-deny:

```text
Continue? [y/N]:
```

Delete is refused while references exist.

## 14. Object Groups

```text
Object Groups
=============

1) List groups
2) Create group
3) View or manage group
4) Back
```

Selected group:

```text
Object Group: <NAME>

1) Overview
2) Members
3) Add member
4) Remove member
5) References
6) Delete
7) Back
```

Cycle creation is rejected. A context-invalid group assignment fails as a whole; invalid members are never silently skipped.

## 15. Remote Access

Canonical submenu:

```text
Remote Access
=============

1) Overview
2) Rules
3) Published Services
4) Service Presets
5) Test access
6) Recent decisions
7) Back
```

Remote Access uses an ordered top-down first-match rulebase with explicit ALLOW/DENY and implicit default DENY.

## 16. Remote Access Rules

List view:

```text
#   NAME               SOURCE       DESTINATION   SERVICE     ACTION   STATUS
10  block-dp1-ssh      external1    dp1           TCP/22      DENY     enabled
20  partner-ssh        external1    internal1     TCP/22      ALLOW    enabled
30  partner-web        external1    internal1     TCP/443     ALLOW    enabled

Implicit Default                                           DENY
```

Rule creation flow:

```text
Name
→ Source
→ Destination
→ Protocol / port
→ Action ALLOW|DENY
→ create Disabled at bottom
→ policy/shadow analysis
→ optional enable
```

Selected rule:

```text
Remote Access Rule: partner-ssh

1) Overview
2) Source
3) Destination
4) Protocol / port
5) Action
6) Enable / Disable
7) Move before / after
8) Explain impact
9) Delete
10) Back
```

Changing order runs shadow/conflict and effective-action analysis.

## 17. Published Services

Canonical submenu:

```text
Published Services
==================

1) List services
2) View service
3) Create service on local/client context where supported
4) Service Presets
5) Back
```

A service view must show effective-target semantics:

```text
Published Service: ssh
Target Mode      : SELF
Local Target     : 127.0.0.1:22
Effective Target : dp1
Public Port      : 6000
Status           : Enabled
```

or:

```text
Published Service: web1
Target Mode      : ROUTED
Effective Target : 10.10.10.20:443
Via              : dp1
Public Port      : 6001
```

Changing target/mode triggers policy-impact analysis.

## 18. Service Presets

```text
Service Presets
===============

1) List presets
2) Create preset
3) View or edit preset
4) Delete preset
5) Back
```

The UI explicitly states:

```text
A Service Preset only supplies initial values.
Changing it does not change existing Published Services.
```

## 19. Remote Access test

Guided flow asks for an actual flow:

```text
Source IP
Destination IP / endpoint
Protocol
Port
```

Result shows:

```text
Source object matches
Destination object matches
Rule trace
First complete match
Published Service match / reachability
Final result
```

Do not label policy-only evaluation as a live connectivity test.

## 20. Internet Access

Canonical submenu:

```text
Internet Access
===============

1) Overview
2) Rules
3) Fixed TCP
4) Test access
5) Recent decisions
6) Back
```

The old Internet Profile UX is superseded by the ordered rulebase.

## 21. Internet Access Rules

List view:

```text
#   NAME              SOURCE       DESTINATION   SERVICE      ACTION   STATUS
10  block-github-db   database     github        HTTPS/443    DENY     enabled
20  approved-web      internal1    external2     HTTPS/443    ALLOW    enabled

Implicit Default                                          DENY
```

Creation/edit/order semantics match Remote Access where meaningful.

Destination selection is context-aware and may include FQDN, public Host, public Network, or a compatible Object Group.

## 22. Fixed TCP

Fixed TCP remains available for approved proxy-unaware use cases.

Its public UX must reference the same Object/policy system rather than inventing a third independent destination-list authority.

```text
Fixed TCP
=========

1) List entries
2) Create entry
3) View or manage entry
4) Back
```

The exact low-level listener model remains implementation-defined, but enablement cannot bypass Internet Access source/destination authorization.

## 23. Internet Access test

Example direct equivalent:

```text
test internet-access 10.10.10.20 google.com 443 https
```

Guided output includes DNS/security validation where relevant, matched Objects, ordered rule trace, and final action.

## 24. AI Access

Canonical submenu:

```text
AI Access
=========

1) Overview
2) AI Principals
3) Access Rules
4) Active / recent operations
5) Test authorization
6) Back
```

AI Access is separate from Remote Access because the decision is capability-oriented rather than packet-oriented. Its rulebase is ordered top-down: first complete match wins, explicit ALLOW/DENY are supported, and no match means implicit DENY.

## 25. AI Principals

```text
AI Principals
=============

1) List principals
2) Add principal
3) View or manage principal
4) Disable / enable principal
5) Revoke credential
6) Back
```

Normal output never reveals raw credentials.

Principal detail shows identity/provider binding, enabled state, last-seen metadata, and rule references.

## 26. AI Access Rules

Example list:

```text
NAME                 PRINCIPAL         TARGETS            CAPABILITIES        STATUS
readonly-audit       chatgpt-support   production-linux   read_file,system    enabled
lab-maintenance      cursor-dev        lab-linux          exec,file-rw        enabled
```

Selected rule:

```text
AI Access Rule: lab-maintenance

1) Overview
2) Principal
3) Targets
4) Capabilities
5) Path scopes
6) Exec constraints
7) Action: ALLOW / DENY
8) Enable / Disable
9) Move before / after
10) Explain impact
11) Delete
12) Back
```

Target selectors are Managed Endpoints and Client Groups. New AI Access rules are created disabled at the bottom. Multiple targets/capabilities within one rule are OR; Principal, Target, Capability, and applicable constraints must all match for a complete rule match.

## 27. AI capability safety

The CLI must warn when a user grants `exec` while describing a role as read-only.

Canonical explanation:

```text
exec can modify the target through shell/OS permissions.
A true read-only AI role requires exec disabled.
```

Path-scope changes and capability additions participate in access-broadening confirmation.

## 28. AI authorization test

Guided test accepts:

```text
Principal
Target
Tool / capability
Path or command metadata where applicable
```

Result shows:

```text
principal status
matching target identity
rule evaluation
capability decision
path/exec constraint decision
final ALLOW/DENY
```

A policy test does not execute the requested operation.

## 29. System

Canonical submenu:

```text
System
======

1) Status
2) Server Settings
3) Audit
4) Revisions
5) Backup & Restore
6) Updates
7) Diagnostics
8) Version Information
9) Back
```

## 30. Status

System status must include control-plane/runtime consistency, for example:

```text
Control DB       : Healthy
DB Revision      : 42
Remote Policy    : revision 42 active
Internet Policy  : revision 42 active
AI Policy        : revision 42 active
MCP Bridge       : Healthy
```

A generation mismatch is surfaced explicitly and must not be collapsed into a generic Healthy state.

## 31. Audit

```text
Audit
=====

1) Recent configuration changes
2) Recent Remote Access decisions
3) Recent Internet Access decisions
4) Recent AI operations
5) Filter / search
6) Back
```

Sensitive payloads are never dumped merely because an audit record exists.

## 32. Revisions

```text
Revisions
=========

1) List revisions
2) View revision
3) Diff revisions
4) Rollback [when implemented and qualified]
5) Back
```

Rollback must itself be a new audited revision and must run normal impact analysis/compilation.

## 33. Backup & Restore

```text
Backup & Restore
================

1) Create backup
2) Validate backup
3) Restore backup
4) Back
```

The UI should describe the backup as a consistent control-plane snapshot, not a raw copy of `drlink.db`.

## 34. Updates

```text
Updates
-------

1) Update Data Relay Link
2) Check Relay Engine (FRP) release
3) Update Relay Engine (FRP)
4) Back
```

Product and Relay Engine versions remain separate.

Stable update paths never silently consume preview/development builds.

## 35. Diagnostics

```text
Diagnostics
===========

1) Run health checks
2) Create support bundle
3) Control-plane integrity checks
4) Runtime-generation checks
5) Back
```

Diagnostics are read-only unless an operation explicitly says it repairs state and the user confirms it.

## 36. Version Information

Canonical fields:

```text
Data Relay Link: <product identity>
Channel: <development|preview|stable>
Source HEAD: <40-char SHA>
Relay Engine (FRP): <version>
Control DB Schema: <version>
```

Do not report `stable` without matching immutable release provenance.

## 37. Root `?`

Bare `?` is domain-oriented, not a parser verb dump.

Example:

```text
Data Relay Link
===============

Clients
  Connect and manage client machines

Objects
  Reusable hosts, networks and destinations

Remote Access
  Inbound access to published services

Internet Access
  Approved outbound Internet connectivity

AI Access
  AI/MCP authorization to managed endpoints

System
  Status, audit, backup, updates and diagnostics

Guided navigation: menu
Advanced commands: help commands
```

## 38. Help topics

Required topics:

```text
help
help clients
help objects
help remote-access
help internet-access
help ai-access
help system
help workflows
help commands
help legacy
```

`help legacy` may explain development-transition aliases if retained temporarily, but legacy names are not shown in normal discovery.

## 39. Tab completion

Completion is:

```text
safe
non-executing
deterministic
context-aware
role-aware
policy-field-aware
```

Examples:

- A Remote Access Source selector only offers Objects valid for that field.
- An Internet Access Destination selector offers FQDN/public Host/public Network compatible resources.
- AI target completion offers Managed Endpoints and Client Groups.
- Secrets are never completion candidates.

## 40. Guided transaction semantics

A guided mutation is staged until final commit.

Canonical behavior:

```text
Back    → one level up
Cancel  → discard the current staged operation
Commit  → run validation/impact/concurrency checks and apply atomically
Exit    → leave CLI
```

A cancelled wizard must not partially mutate authoritative state.

## 41. Concurrency feedback

If the selected entity changed while the operator was editing:

```text
Object changed while you were editing it.
No changes were applied.
Review current state and retry.
```

The UI never silently overwrites newer state.

## 42. Policy-impact presentation

Security-relevant edits should summarize effect in operator terms:

```text
Policy behavior will change

Access broadened: YES
Access narrowed: NO
Affected rules: 2
Newly shadowed rules: 1

Before: DENY
After : ALLOW via remote-access #20 partner-ssh

Continue? [y/N]:
```

The default answer for broadening is No.

## 43. First-match explanation

Explain output explicitly distinguishes:

```text
MATCH
NO MATCH
NOT EVALUATED — earlier complete match already decided
```

This is essential for debugging ordered policy.

## 44. REPL vs shell hints

Inside:

```text
drlink>
```

show:

```text
show objects
set remote-access partner-ssh enabled
```

At a shell, show:

```text
sudo drlink show objects
sudo drlink set remote-access partner-ssh enabled
```

Never tell a user already inside the REPL to type a second `drlink` prefix.

## 45. Backend isolation

Normal operator output must not expose internal backend commands, SQL, table names, raw FRP helper binaries, or generated runtime file names unless explicitly requested for diagnostics.

Public interface:

```text
drlink
```

## 46. Discovery consistency

These surfaces use the same nouns:

```text
?
help
menu
Tab display
errors
examples
documentation
```

Do not call the same concept Object Group in one surface and ACL Group in another.

## 47. Destructive operation safety

Operations requiring clear confirmation include:

- unset client
- release a Published Service reservation
- delete a referenced policy resource after references are cleared
- widen network access
- grant AI exec/write/upload/download
- restore backup
- rollback revision
- disable a policy enforcement component

Confirmation describes user-visible effect, not merely internal implementation.

## 48. Canonical UX invariants

```text
CLI_DIRECT_GRAMMAR=ACTION_FIRST

SERVER_ROOT=
Clients
Objects
Remote Access
Internet Access
AI Access
System
Help
Exit

CLIENT_ROOT=
Published Services
System
Help
Exit

OBJECT_MODEL=NEUTRAL
CLIENT_GROUP_NE_OBJECT_GROUP=YES
SERVICE_PROFILE_PUBLIC_RESOURCE=NO
SERVICE_PRESET_PUBLIC_RESOURCE=YES
INTERNET_PROFILE_PUBLIC_RESOURCE=NO
ACL_PRIMARY_PUBLIC_RESOURCE=NO
ORDERED_RULEBASE_VISIBLE=YES
FIRST_MATCH_EXPLAINABLE=YES
IMPLICIT_DEFAULT_DENY_VISIBLE=YES
POLICY_IMPACT_VISIBLE=YES
BACKEND_TOOLS_USER_VISIBLE=NO
```

## 49. Testing contract

CLI regressions must protect at least:

```text
role-aware roots
canonical nouns
root ? domains
help topic parity
Tab safety/context filtering
Object CRUD/reference protection
Object Group cycle rejection
Managed Endpoint lifecycle restrictions
SELF/ROUTED Published Service display
rule create-disabled-at-bottom semantics
ALLOW/DENY
before/after ordering
first-match explain trace
shadow warnings
policy-impact confirmation
optimistic concurrency failure
AI Principal secret non-disclosure
AI capability/path target selection
REPL vs shell hints
no backend command leakage
version/provenance fields
```

## 50. Final UX principle

A first-time operator should think:

```text
I need to connect a machine
→ Clients

I need reusable network identities
→ Objects

I need to control inbound support access
→ Remote Access

I need to allow approved Internet access
→ Internet Access

I need to allow an AI tool to operate on a private host
→ AI Access

I need to maintain Data Relay Link itself
→ System
```

An experienced operator can skip menus and use the direct grammar without losing any safety guarantees.
