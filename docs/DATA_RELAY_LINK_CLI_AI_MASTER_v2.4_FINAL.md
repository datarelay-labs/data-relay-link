# Data Relay Link v2.4 — CLI & AI Configuration Master

**Status:** Canonical Source of Truth — Final Implementation Freeze
**Scope:** DRLink CLI, Server/Agent roles, Objects/Groups, Access Policy, Remote Service, Relay Host, Fixed TCP, AI Identity, AI-generated CLI, ConfigurationBundle, validation/error/rollback semantics, and end-to-end operator scenarios
**Version line:** v2.4
**Last updated:** 2026-09-18
**Revision:** FINAL — implementation-ready simulation PASS

---

## 0. Purpose and authority

This document is the single authoritative specification for Data Relay Link (DRLink) CLI and AI-assisted configuration behavior.

If another implementation, help text, example, test, or document disagrees with this document, this document defines the intended CLI/UX behavior.

The goals are:

- a small and consistent mental model;
- the same semantics for human Wizard, AI one-shot CLI, and ConfigurationBundle;
- safe copy/paste workflows;
- no partial configuration on validation failure;
- clear separation between DRLink Server configuration and Agent Host local configuration;
- predictable access-policy behavior;
- stable Remote Service endpoints;
- useful error messages that both humans and AI can act on.

Examples in this document are normative unless explicitly marked as illustrative.

---

# 1. Core mental model

The user should only need to understand the following primary concepts.

```text
Managed Host / DRLink Agent

Network Object
Network Group

Service Object
Service Group

Permission Object
Permission Group

AI Identity

Remote Service

Remote Access
Internet Access
AI Access

BLACKLIST / WHITELIST
```

The main relationships are:

```text
Managed Host + Service Object
→ Remote Service
→ actual connectivity / endpoint

Remote Access
Internet Access
AI Access
→ policy evaluation
→ decides whether an authenticated/identified request is allowed
```

A policy Rule does not create connectivity.

A Remote Service creates or represents connectivity.

---

# 2. CLI execution contexts

DRLink has two configuration contexts.

## 2.1 DRLink Server CLI

The Server CLI manages:

```text
Managed Hosts
Enrollments
Network Objects / Groups
Service Objects / Groups
Remote Access
Internet Access
AI Identities
Permission Objects / Groups
AI Access
AI Access Log
Server-side configuration/revision/audit operations
```

The Server may inspect Agent and Remote Service state, but it does not perform Agent lifecycle operations.

---

## 2.2 Agent Host local CLI

The Agent Host CLI manages only the local Agent and Remote Services owned by that Agent Host.

It manages:

```text
Agent status
Agent lifecycle
Remote Services
Agent-local diagnostics
Agent-local ConfigurationBundle
```

Remote Service mutation happens on the Agent Host that owns the Remote Service.

If the Remote Service destination is another host, the current Agent Host acts as the Relay Host.

---

## 2.3 Command notation used in this document

Commands are shown as commands entered inside the DRLink CLI:

```text
drlink> show status
drlink> set remote-access block-partner
```

For shell execution, prefix the same command with `drlink`:

```bash
drlink show status
drlink set remote-access block-partner
```

When AI is asked to generate a command without further context, it should default to the DRLink CLI form and clearly say that the command is intended for the `drlink>` prompt.

---

# 3. Common command verbs

The common command meanings are fixed.

```text
show
→ read-only
→ never mutates authoritative state

set
→ create
→ edit
→ enable / disable

unset
→ remove / delete / reset when explicitly targeting policy state

test
→ simulate / validate / explain
→ never mutates authoritative state

system
→ system operations, configuration import/export/diff/apply,
  diagnostics, revisions, backup/restore, update, uninstall
```

`show` and `test` must never allocate ports, create Objects, or change runtime state.

---

# 4. Managed Host and DRLink Agent

## 4.1 Managed Host

A Managed Host is a real server, PC, VM, Mac, or other host managed through DRLink.

Examples:

```text
ubuntu-prod
windows-admin
macstudio-lab
branch-gateway
```

A Managed Host is also a Network Object for policy-selection purposes.

Conceptually:

```text
Network Object
├── IP
├── CIDR
├── FQDN
└── Managed Host
```

A Managed Host can be selected directly anywhere that its Network Object form is valid.

`show network-objects` includes registered Managed Hosts as Network Objects with type `Managed Host`.

Example:

```text
NAME           TYPE
office-admin   IP
github         FQDN
ubuntu-prod    Managed Host
```

Managed Host lifecycle remains under Managed Host commands.

Therefore:

```text
set network-object
unset network-object
```

create/delete only ordinary IP/CIDR/FQDN Network Objects.

If a user attempts to delete a Managed Host through `unset network-object`:

```text
ERROR:
Network Object 'ubuntu-prod' is a Managed Host.

Use:
  unset managed-host ubuntu-prod

No changes were applied.
```

Read-only Network Object reference inspection remains valid for Managed Hosts because they may be used by Access Policy selectors.

---

## 4.2 DRLink Agent

The DRLink Agent is the software installed on a Managed Host.

```text
Managed Host
    └── DRLink Agent
```

Server inspection examples:

```text
show managed-hosts
show managed-host ubuntu-prod
show managed-host ubuntu-prod agent
show managed-host ubuntu-prod addresses
show managed-host ubuntu-prod remote-services
```

Agent lifecycle is local to the Agent Host.

---

# 5. Network Object

A normal user-created Network Object is one of:

```text
IP
CIDR
FQDN
```

Examples:

```text
office-admin
  IP
  203.0.113.10
```

```text
corp-network
  CIDR
  10.10.0.0/16
```

```text
github
  FQDN
  github.com
```

Human creation:

```text
set network-object github
```

Wizard:

```text
Create Network Object
=====================

Type:
1) IP
2) CIDR
3) FQDN

Select: 3

Value:
github.com

Review
------
Name  : github
Type  : FQDN
Value : github.com

1) Apply
2) Edit
3) Cancel
```

AI one-shot creation:

```text
set network-object github type fqdn value github.com
```

Another example:

```text
set network-object office-admin type ip value 203.0.113.10
```

---

# 6. Network Group

A Network Group is an optional reusable group of Network Objects.

Example:

```text
approved-admins
├── office-admin
├── vpn-admin
└── partner-admin
```

Human creation:

```text
set network-group approved-admins
```

AI one-shot example:

```text
set network-group approved-admins members office-admin,vpn-admin,partner-admin
```

A Network Group is not required when a single Network Object is sufficient.

A group is a flat collection for CLI purposes.

---

# 7. Internet Access Network selector validation

Internet Access distinguishes source and destination selectors.

Source may use:

```text
IP
CIDR
FQDN
Managed Host
Network Group containing any of the above
```

This allows a Managed Host to express the natural intent:

```text
ubuntu-prod
→ github.com
→ HTTPS
```

without creating a second IP wrapper for the same host.

Destination may use:

```text
IP
CIDR
FQDN
Network Group containing only IP/CIDR/FQDN Network Objects
```

A Managed Host is not valid as an Internet Access destination.

A Network Group selected as an Internet Access destination is rejected if any member is a Managed Host.

Example:

```text
ERROR:
Network Group 'mixed-destinations' contains Managed Host 'ubuntu-prod'.

Managed Hosts are valid Internet Access sources,
but cannot be used as Internet Access destinations.

No changes were applied.
```

This validation applies before any authoritative state mutation.

---

# 8. Service Object

A Service Object represents a network service.

The supported Service Object types are:

```text
TCP
UDP
Fixed TCP
```

Typical built-in or reusable examples:

```text
ssh
  TCP/22

http
  TCP/80

https
  TCP/443

rdp
  TCP/3389

postgres
  TCP/5432
```

---

## 8.1 TCP / UDP Service Object

Human creation:

```text
set service-object postgres
```

Normal public Wizard (v2.4):

```text
Create Service Object
=====================

Service Object type
-------------------
1) SSH
2) HTTP
3) HTTPS
4) RDP
5) Custom TCP
6) Fixed TCP

Select: 5

Port:
5432

Review
------
Name : postgres
Type : TCP
Port : 5432

1) Apply
2) Edit
3) Cancel
```

Preset mapping:

```text
SSH        → TCP/22
HTTP       → TCP/80
HTTPS      → TCP/443
RDP        → TCP/3389
Custom TCP → TCP/<user port>   (normal published-service port pool)
Fixed TCP  → Fixed TCP/<destination port>  (public endpoint port is allocated separately from the Fixed TCP endpoint pool)
```

UDP is not offered in the normal public Service Object Wizard. v2.4 Remote Service
consumers are TCP / Fixed TCP only. UDP remains creatable via explicit AI/one-shot
commands where a non-Remote-Service consumer still needs it.

AI one-shot:

```text
set service-object postgres type tcp port 5432
```

UDP example (explicit; not Wizard menu):

```text
set service-object dns-udp type udp port 53
```

Feature-specific protocol support is validated at the point where the Service Object is used.

When a Wizard expects a numeric menu choice and the operator pastes text that
clearly resembles a DRLink command, the Wizard must reject the input with guidance
to leave the Wizard (Back/Cancel) and run the command at the `drlink>` prompt.
It must not execute pasted commands inside the Wizard.

---

# 9. Fixed TCP Service Object

Fixed TCP is a Service Object subtype.

It is not configured as a separate policy model.

A Fixed TCP Service Object defines the destination TCP service port.

Example:

```text
Service Object
Name : legacy-db
Type : Fixed TCP
Port : 1521
```

Human creation:

```text
set service-object legacy-db
```

Wizard:

```text
Create Service Object
=====================

Service Object type
-------------------
1) SSH
2) HTTP
3) HTTPS
4) RDP
5) Custom TCP
6) Fixed TCP

Select: 6

Destination Port:
1521

Review
------
Name     : legacy-db
Type     : Fixed TCP
Protocol : TCP
Port     : 1521

1) Apply
2) Edit
3) Cancel
```

AI one-shot:

```text
set service-object legacy-db type fixed-tcp port 1521
```

The user never selects the external listen port.

The external endpoint is allocated when a Remote Service uses this Fixed TCP Service Object.

A Remote Service using a Fixed TCP Service Object uses the Fixed TCP managed port pool.

The Fixed TCP pool is separate from the normal Remote Service endpoint-port pool.

Pool ranges are implementation-managed and do not need to be part of normal user configuration.

---

# 10. Service Group

A Service Group is an optional reusable group of Service Objects.

Examples:

```text
web-services
├── http
└── https
```

```text
admin-services
├── ssh
├── https
└── rdp
```

Human creation:

```text
set service-group web-services
```

AI one-shot:

```text
set service-group web-services members http,https
```

Access Rules may use either a Service Object or a Service Group.

A Remote Service uses one Service Object, not a Service Group.

---

# 11. Permission Object

A Permission Object contains one or more DRLink permissions.

Available permission concepts include:

```text
host-info
process-read
file-read
command-exec
file-write
file-upload
file-download
```

Example:

```text
Permission Object: read-only

Permissions:
  host-info
  process-read
  file-read
```

Another:

```text
Permission Object: operator

Permissions:
  host-info
  process-read
  file-read
  command-exec
  file-write
  file-upload
  file-download
```

Human creation:

```text
set permission-object read-only
```

AI one-shot:

```text
set permission-object read-only permissions host-info,process-read,file-read
```

---

# 12. Permission Group

A Permission Group is an optional group of Permission Objects.

Human creation:

```text
set permission-group operations
```

AI one-shot example:

```text
set permission-group operations members read-only,operator
```

AI Access Rules may use either a Permission Object or Permission Group.

---

# 13. AI Identity

AI Access uses an authenticated AI Identity as its source.

Examples:

```text
claude
chatgpt
custom-ai
```

An AI Identity is bound to a verified authentication identity.

The user does not create trust merely by assigning a display name.

---

## 13.1 AI Identity onboarding

The normal Server CLI path is:

```text
set ai-identity <NAME>
```

or the menu flow:

```text
AI Access
→ Connect AI
```

Typical guided flow:

```text
Connect AI
==========

Name:
claude

Type:
1) Interactive AI
2) Automation / Custom AI
```

Interactive AI:

```text
OAuth Authorization Code
→ verification
→ AI Identity binding
→ VERIFIED
```

Automation / Custom AI:

```text
OAuth Client Credentials
→ verification
→ AI Identity binding
→ VERIFIED
```

AI authentication and AI Access policy evaluation are separate steps.

```text
Authentication
→ identify the AI

AI Access
→ decide what that authenticated identity may access
```

An unauthenticated AI request does not become allowed because policy enforcement is disabled.

---

# 14. Access Policy overview

There are three Access Policy areas:

```text
Remote Access
Internet Access
AI Access
```

Each Access Policy has:

```text
POLICY MODE
├── BLACKLIST
└── WHITELIST

ENFORCEMENT
├── ENABLED
└── DISABLED
```

The mode alone determines the meaning of matching Rules.

---

# 15. Initial state

Immediately after installation, before an Access Policy has been configured:

```text
No Policy
No Rules
Effective access = ALLOW
```

The CLI should communicate this clearly.

Example first screen:

```text
Data Relay Link

No access restrictions are currently configured.
Access is allowed by default.

Access policies:
  Remote Access
  Internet Access
  AI Access

Policy modes:
  Blacklist — rules define what to block
  Whitelist — rules define what to allow

Reusable objects:
  Network Objects / Groups
  Service Objects / Groups
  Permission Objects / Groups

Objects can also be created while creating a rule.

Type:
  menu
  help
```

---

# 16. BLACKLIST semantics

In BLACKLIST mode:

```text
Any enabled Rule matches
→ DENY

No enabled Rule matches
→ ALLOW
```

Rules define what to block.

Example:

```text
Remote Access
Mode: BLACKLIST

Rule: block-partner-ssh

Source      : partner-office
Destination : ubuntu-prod
Service     : ssh
Enabled     : YES
```

Effective result:

```text
Match    → DENY
No match → ALLOW
```

---

# 17. WHITELIST semantics

In WHITELIST mode:

```text
Any enabled Rule matches
→ ALLOW

No enabled Rule matches
→ DENY
```

Rules define what to allow.

Example:

```text
Internet Access
Mode: WHITELIST

Rule: github-https

Source      : office-network
Destination : github
Service     : https
Enabled     : YES
```

Effective result:

```text
Match    → ALLOW
No match → DENY
```

Several matching Rules do not create a conflict.

---

# 18. First Rule and Policy Mode

When a human creates the first Rule in an unconfigured Access Policy, the Wizard asks for the mode.

Example:

```text
set remote-access block-partner
```

```text
Remote Access Policy
====================

No access policy is configured yet.

Choose policy mode:

1) Blacklist
   Allow by default.
   Rules define what to block.

2) Whitelist
   Deny by default.
   Rules define what to allow.

Select:
```

The selected mode is saved with the policy.

---

# 19. AI one-shot first Rule and Policy Mode

AI one-shot commands are non-interactive.

If no Policy Mode exists yet, the first Rule must include the mode.

Example:

```text
set internet-access github-https mode whitelist source office-network destination github service https enabled
```

Example:

```text
set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled
```

Rules:

```text
No existing Policy Mode
→ mode is required in the first AI one-shot Rule

Policy Mode already exists
→ mode may be omitted

Existing BLACKLIST + command says mode whitelist
→ reject

Existing WHITELIST + command says mode blacklist
→ reject
```

Example error:

```text
ERROR:
Remote Access is already configured in BLACKLIST mode.

The requested command specifies WHITELIST.

Reset the Remote Access policy before configuring a different mode.

No changes were applied.
```

---

# 20. Rule fields

## 20.1 Remote Access Rule

```text
name
source
destination
service
enabled / disabled
```

Selectors:

```text
source
→ Network Object / Network Group

destination
→ Network Object / Network Group

service
→ Service Object / Service Group
```

Remote Access governs access to Remote Services.

Because Remote Service supports TCP and Fixed TCP only, a Remote Access Rule rejects:

```text
UDP Service Object
Service Group containing any UDP Service Object
```

Example:

```text
ERROR:
Service Group 'mixed-services' contains UDP Service Object 'dns-udp'.

Remote Access supports TCP and Fixed TCP Remote Services only.

No changes were applied.
```

---

## 20.2 Internet Access Rule

```text
name
source
destination
service
enabled / disabled
```

Internet Access source selectors may include Managed Hosts and Groups containing Managed Hosts.

Internet Access destination selectors reject a Managed Host and reject any Group containing a Managed Host.

---

## 20.3 AI Access Rule

```text
name
source      → AI Identity
destination → Network Object / Network Group
permission  → Permission Object / Permission Group
enabled / disabled
```

---

# 21. Human Rule Wizard

Example:

```text
set remote-access block-partner-ssh
```

In BLACKLIST mode:

```text
Create Remote Access Rule
=========================

Mode:
  BLACKLIST

This rule blocks matching access.

Source:
partner-office

Destination:
ubuntu-prod

Service:
ssh

Enabled:
1) Yes
2) No

Review
======

Name        : block-partner-ssh
Source      : partner-office
Destination : ubuntu-prod
Service     : ssh
Enabled     : YES

Effect:
  Matching access will be BLOCKED.
  All other access remains ALLOWED.

1) Apply
2) Edit
3) Cancel
```

In WHITELIST mode:

```text
Effect:
  Matching access will be ALLOWED.
  All other access remains DENIED.
```

---

# 22. Inline Object creation in Wizards

A Rule Wizard may create missing Objects without forcing the user to exit the Wizard.

Example Source step:

```text
Source
------

1) office-admin
2) partner-office
3) + Create Network Object
4) + Create Network Group
```

Service step:

```text
Service
-------

1) ssh
2) https
3) postgres
4) + Create Service Object
5) + Create Service Group
```

AI Permission step:

```text
Permission
----------

1) read-only
2) operator
3) + Create Permission Object
4) + Create Permission Group
```

Created draft Objects return the user to the original Rule Wizard.

None of these draft Objects are authoritative until the final Apply succeeds.

---

# 23. Wizard atomicity

A Wizard represents one draft Change Plan.

```text
Wizard
→ Object creation/edit
→ Rule creation/edit
→ Review
→ validation
→ Apply
```

Before Apply, authoritative state is unchanged.

Cancel:

```text
No changes were applied.
```

If a user creates a draft Network Object and then cancels the Rule Wizard, the Network Object must not remain behind.

---

# 24. Create/Edit entry point

For named resources:

```text
set <RESOURCE> <NAME>
```

means:

```text
Name does not exist
→ Create Wizard

Name exists
→ Edit Wizard
```

Example:

```text
set remote-access block-partner-ssh
```

Existing Rule:

```text
Remote Access: block-partner-ssh

1) Change Source
2) Change Destination
3) Change Service
4) Enable / Disable
5) Review
6) Cancel
```

Review must show the delta.

```text
Before
------
Service : ssh

After
-----
Service : admin-services
```

---

# 25. Invalid input behavior

Invalid input does not restart the whole Wizard.

Example:

```text
ERROR: Invalid CIDR '10.10.999.0/24'.

Enter a valid CIDR.
```

The user remains on the same step.

Previous valid draft input is preserved.

No authoritative mutation occurs.

---

# 26. Rule enabled/disabled semantics

Rule-level disabled means:

```text
This Rule is excluded from policy evaluation.
```

It does not disable the entire policy.

Important WHITELIST example:

```text
WHITELIST
Enabled Rules: 1

Disable the last enabled Rule
→ Enabled Rules: 0
→ Effective: DENY ALL
```

Before Apply:

```text
WARNING:
This change leaves the WHITELIST with no enabled rules.

Effective access after Apply:
  DENY ALL
```

BLACKLIST equivalent:

```text
BLACKLIST
Enabled Rules: 0
→ Effective: ALLOW ALL
```

---

# 27. Last Rule deletion

Deleting the last Rule does not delete or reset Policy Mode.

```text
BLACKLIST + 0 Rules
→ Effective ALLOW ALL
```

```text
WHITELIST + 0 Rules
→ Effective DENY ALL
```

Rule deletion and Policy Reset are different operations.

---

# 28. Policy Enforcement disable/enable

Disable policy enforcement:

```text
set remote-access disabled
set internet-access disabled
set ai-access disabled
```

Effect:

```text
Mode              → preserved
Rules             → preserved
Rule enabled state→ preserved
Enforcement       → DISABLED
Effective policy  → ALLOW ALL
```

Example:

```text
Remote Access
=============

Mode        : WHITELIST
Enforcement : DISABLED
Effective   : ALLOW ALL

Saved rules remain unchanged.
```

Re-enable:

```text
set remote-access enabled
```

The previously saved mode and Rules immediately become effective again.

For AI Access, authentication still remains mandatory even while policy enforcement is disabled.

---

# 29. Policy Reset

Policy Reset returns one Access Policy area to its original unconfigured state.

Canonical CLI:

```text
unset remote-access policy
unset internet-access policy
unset ai-access policy
```

Effect:

```text
Mode  → removed
Rules → removed

Result:
No Policy
No Rules
Effective access = ALLOW
```

Reset is destructive and requires explicit confirmation.

Example:

```text
WARNING:
This will remove the Remote Access policy mode and all Remote Access rules.

Effective access after reset:
  ALLOW

Continue? [y/N]
```

AI Access policy reset does not remove AI Identity authentication.

---

# 30. Policy Mode replacement

A configured Access Policy is not directly converted from BLACKLIST to WHITELIST or vice versa.

To replace the mode:

```text
1. Export or record the current configuration if needed
2. Reset the Access Policy
3. Create the first Rule in the desired new mode
4. Recreate the required Rules
```

This prevents silent reversal of every existing Rule's meaning.

---

# 31. Remote Service

A Remote Service is configured locally on the Agent Host.

It provides actual connectivity.

```text
Managed Host / Relay Host
+ Destination
+ Service Object
→ Remote Service
→ DRLink endpoint
```

Remote Access policy decides whether requests to that connectivity are allowed.

Creating or deleting an Access Rule does not create or delete the Remote Service.

---

# 32. Agent local Remote Service CLI

Agent local commands:

```text
show remote-services
show remote-service <NAME>

set remote-service <NAME>
unset remote-service <NAME>
```

Human creation:

```text
set remote-service ssh-access
```

Direct-host Wizard:

```text
Create Remote Service
=====================

Destination:
1) This Host (ubuntu-prod)
2) Select another destination

Select: 1

Service:
1) ssh
2) https
3) postgres

Select: 1

Enabled:
1) Yes
2) No

Review
------
Name        : ssh-access
Destination : ubuntu-prod
Relay Host  : -
Service     : ssh
Enabled     : YES

1) Apply
2) Edit
3) Cancel
```

Result:

```text
Remote Service activated.

Name        : ssh-access
Destination : ubuntu-prod
Service     : ssh
Status      : HEALTHY
Endpoint    : drlink.example:6101

Connection:
  ssh -p 6101 user@drlink.example
```

AI one-shot in Agent context:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

---

# 33. Relay Host Remote Service

If the destination is not the current Agent Host, the current Agent Host acts as the Relay Host.

Environment:

```text
branch-gateway
  DRLink Agent installed

internal-db
  no DRLink Agent
```

Run on `branch-gateway`:

```text
set remote-service internal-db-postgres
```

Wizard:

```text
Destination:
internal-db

Service:
postgres

Enabled:
Yes

Review
------
Name        : internal-db-postgres
Destination : internal-db
Relay Host  : branch-gateway
Service     : postgres
Enabled     : YES
```

The Relay Host is implied by the Agent Host on which the command is executed.

There is no need for a separate Relay-host mutation command.

AI one-shot on `branch-gateway`:

```text
set remote-service internal-db-postgres destination internal-db service postgres enabled
```

---

# 34. Remote Service destination validation

A Remote Service represents one actual target service.

The destination must resolve to a single target.

Allowed examples:

```text
This Host
Managed Host
single IP Network Object
FQDN Network Object
```

A CIDR or multi-member Network Group is rejected for Remote Service destination selection.

Example:

```text
ERROR:
Remote Service destination must resolve to a single target.

Network Group 'database-fleet' contains multiple targets.

No changes were applied.
```

---

# 35. Remote Service Service selection

A Remote Service uses exactly one Service Object.

A Service Group cannot be selected for a Remote Service.

Remote Service transport support is:

```text
TCP       → supported
Fixed TCP → supported
UDP       → not supported
```

UDP Service Objects may exist for other policy/use cases, but they cannot be selected by a Remote Service.

The Agent Host maintains a synchronized local catalog of canonical Server-side Service Objects and Network Objects used for validation and selection. A temporary Server disconnect does not by itself prevent Remote Service create/edit.

Agent↔Server management operations are authenticated with the enrolled Agent management identity. Operators continue to use `drlink set remote-service`, `drlink show remote-service`, and `drlink system synchronize`; signing is internal.

Example selectable services:

```text
Service
-------

1) ssh         TCP/22
2) https       TCP/443
3) postgres    TCP/5432
4) legacy-db   Fixed TCP/1521
```

A UDP Service Object is rejected:

```text
ERROR:
Service Object 'dns-udp' uses UDP.

Remote Service supports TCP and Fixed TCP services only.

No changes were applied.
```

If a required reference is not available in the Agent's synchronized catalog:

```text
ERROR:
Service Object 'oracle-listener' is not available in the local synchronized catalog.

No changes were applied.

Create/synchronize the required Service Object and retry.
```

The failure is caused by an unresolved dependency, not merely by the Agent being temporarily disconnected from the Server.

---

# 36. Remote Service status

Remote Service user-facing states:

```text
HEALTHY
DEGRADED
DISABLED
```

## HEALTHY

```text
Configuration valid
Agent connected
Destination reachable
Endpoint usable
```

## DEGRADED

```text
Configuration valid
Endpoint/port reservation preserved
But current runtime connectivity is unavailable
```

Typical reasons:

```text
Relay destination unreachable
Agent temporarily disconnected
DRLink Server temporarily unreachable
Target service temporarily unavailable
New endpoint pending Server-side allocation/activation
```

## DISABLED

```text
User intentionally disabled the Remote Service
Configuration preserved
Endpoint/port reservation preserved
Traffic not active
```

---

# 37. Valid-but-unreachable Relay destination

Reachability failure does not invalidate a correct Remote Service configuration.

Example:

```text
Remote Service created.

Name        : internal-db-postgres
Destination : internal-db
Relay Host  : branch-gateway
Service     : postgres
Status      : DEGRADED
Endpoint    : drlink.example:6102

Reason:
  Destination is currently unreachable from Relay Host.

Configuration was saved.
The service will become available automatically when connectivity is restored.
```

When connectivity returns:

```text
DEGRADED
→ HEALTHY
```

No reconfiguration and no endpoint reallocation are required.

Invalid configuration is different.

Examples that fail creation:

```text
Destination Object does not exist
Service Object does not exist
Service value invalid
Configuration structurally invalid
Unsupported combination
```

These produce:

```text
ERROR
No changes were applied.
```

---

# 37.1 Agent/Server disconnect during Remote Service create or edit

A temporary Agent-to-Server disconnect does not make an otherwise valid Remote Service configuration invalid.

The Agent may create or edit a Remote Service using locally available synchronized Object metadata.

For an existing Remote Service with an already assigned endpoint:

```text
Server temporarily unreachable
→ configuration edit allowed
→ existing endpoint reservation retained
→ status DEGRADED while required runtime synchronization is unavailable
→ reconnect
→ synchronize/activate
→ HEALTHY
```

For a new Remote Service that does not yet have a Server-assigned endpoint:

```text
configuration valid
→ save configuration
→ Status: DEGRADED
→ Endpoint: Pending allocation
```

Example:

```text
Remote Service created.

Name        : ssh-access
Destination : ubuntu-prod
Service     : ssh
Status      : DEGRADED
Endpoint    : Pending allocation

Reason:
  DRLink Server is currently unreachable.

Configuration was saved.
Endpoint allocation and activation will complete automatically after reconnect.
```

After reconnect:

```text
Server synchronization
→ endpoint/port allocation
→ runtime activation
→ HEALTHY
```

A previously allocated endpoint is never replaced merely because of temporary disconnection.

If a required Object or Service reference cannot be resolved from locally synchronized metadata, dependency validation fails and no change is saved.

---

# 38. Remote Service endpoint lifecycle

Remote Service endpoint identity is stable.

```text
CREATE while Server endpoint allocation is available
→ endpoint port allocated

CREATE while Server endpoint allocation is temporarily unavailable
→ configuration saved
→ DEGRADED
→ endpoint Pending allocation
→ allocate/activate automatically after reconnect

Agent restart
→ reservation retained

Temporary Agent disconnect
→ reservation retained
→ state may become DEGRADED

Agent reconnect
→ same endpoint restored

Remote Service disable
→ reservation retained

Remote Service enable
→ same endpoint used

Destination/service edit within the same endpoint-pool class
→ endpoint retained

unset remote-service <NAME>
→ Remote Service deleted
→ port returned

Managed Host/Agent permanently removed
→ owned Remote Services cleaned up
→ ports returned
```

Temporary runtime failure must not unexpectedly change the public endpoint.

If `unset remote-service <NAME>` is executed while the Agent cannot currently reach the Server:

```text
local desired configuration
→ Remote Service removed

Server-side endpoint release
→ synchronized when connectivity returns
```

Until synchronization completes, the Server may still show the previously known Remote Service as unavailable/DEGRADED. Its endpoint reservation is not reused for another service before the Server processes the deletion.

After reconnect:

```text
delete synchronization
→ endpoint reservation released
→ Server inventory updated
```

No additional user action is required.

---

# 39. Normal Remote Service pool and Fixed TCP pool

Normal Remote Services and Remote Services using Fixed TCP Service Objects use separate managed port pools.

The pools must not overlap.

A Fixed TCP pool exhaustion does not steal a port from an existing Remote Service.

When endpoint allocation is available during create/apply and the required pool is already exhausted:

```text
ERROR:
No Fixed TCP ports are available.

No changes were applied.
```

If a new Remote Service was validly created while the Server was temporarily unreachable, endpoint capacity could not be checked at that time. If the pool is exhausted when synchronization later occurs:

```text
Configuration : retained
Status        : DEGRADED
Endpoint      : Pending allocation
Reason        : No endpoint port is currently available
```

The service automatically retries allocation when capacity becomes available.

---

# 40. Editing across endpoint-pool classes

An existing Remote Service cannot be edited in-place across the normal Remote Service pool and Fixed TCP pool.

Example:

```text
ssh-access
Service : ssh
```

Attempt:

```text
Change Service → legacy-db (Fixed TCP)
```

Result:

```text
ERROR:
The Service type cannot be changed between standard TCP and Fixed TCP
for an existing Remote Service.

Delete and recreate the Remote Service.

No changes were applied.
```

The same restriction applies in the reverse direction.

This preserves endpoint-pool integrity and prevents hidden endpoint changes.

A Service Object edit must not bypass this protection.

If a Service Object is referenced by one or more Remote Services:

```text
TCP → Fixed TCP
Fixed TCP → TCP
TCP → UDP
```

is rejected because it changes endpoint-pool class or changes the Service into a transport unsupported by Remote Service.

Example:

```text
ERROR:
Service Object 'app-service' is referenced by Remote Services and cannot
change from TCP to Fixed TCP.

References:
  ubuntu-prod / app-access

No changes were applied.
```

Safe edits within the same Remote Service-compatible class are allowed.

Examples:

```text
TCP/22   → TCP/2222
Fixed TCP/1521 → Fixed TCP/1522
```

The public endpoint reservation remains stable and Review must show the affected Remote Services and target-service change.

---

# 41. Fixed TCP Remote Service example

Server creates the Service Object:

```text
set service-object legacy-db
```

```text
Type : Fixed TCP
Port : 1521
```

On the Agent/Relay Host:

```text
set remote-service legacy-db-access
```

```text
Destination : internal-db
Service     : legacy-db
```

Result:

```text
Remote Service activated.

Name        : legacy-db-access
Destination : internal-db
Relay Host  : branch-gateway
Service     : legacy-db
Status      : HEALTHY
Endpoint    : drlink.example:6201
```

The user is given the actual endpoint:

```text
drlink.example:6201
```

not merely the assigned port number.

Access-policy evaluation uses the Fixed TCP Service Object in exactly the same way as other Service Objects.

---

# 42. Remote Service duplicate validation

On one Agent Host, the same effective:

```text
Destination + Service Object
```

combination should not be created twice under different Remote Service names.

Example:

```text
ERROR:
A Remote Service already exists for:

  Destination : ubuntu-prod
  Service     : ssh

Existing Remote Service:
  ssh-access

No changes were applied.
```

This is ordinary validation and prevents duplicate public endpoints for an identical local binding.

---

# 43. Server visibility of Remote Services

Remote Service mutation is Agent-local.

The Server can inspect Remote Service state.

Example:

```text
show managed-host ubuntu-prod remote-services
```

```text
Remote Services
===============

NAME         DESTINATION   SERVICE   ENDPOINT                 STATUS
ssh-access   ubuntu-prod   ssh       drlink.example:6101      HEALTHY
```

Relay example:

```text
show managed-host branch-gateway remote-services
```

```text
NAME                  DESTINATION   SERVICE    ENDPOINT                 STATUS
internal-db-postgres  internal-db   postgres   drlink.example:6102      DEGRADED
```

The Server does not use these read commands to mutate Agent-local Remote Service configuration.

---

# 44. Access-policy test/explain commands

Policy tests do not mutate state.

Remote Access:

```text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
```

Internet Access:

```text
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
```

AI Access:

```text
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
```

Typical output:

```text
Remote Access Test
==================

Mode        : BLACKLIST
Enforcement : ENABLED

Source      : office-admin
Destination : ubuntu-prod
Service     : ssh

Matched Rules:
  block-untrusted-ssh

Effective Result:
  DENY
```

When relevant, Remote Service runtime state may also be shown:

```text
Remote Service:
  ssh-access

Status:
  DEGRADED

Policy Result:
  ALLOW

Connectivity Result:
  UNAVAILABLE
```

This distinguishes policy authorization from runtime reachability.

When a public test selector is a Network Group, Service Group, or Permission Group,
the test expands every leaf member in stable sorted order and evaluates each concrete
combination with the same atomic/runtime evaluators used for single Objects. Top-level
Effective Result is ALLOW only when every expanded member/combination is ALLOW; mixed
outcomes aggregate to DENY and list Member Results so the mixed outcome is visible.
Single Object / Service / Permission Object / atomic permission tests keep the previous
scalar output shape.

---

# 45. Object and identity reference-safe deletion

A referenced Object is not deleted while Rules depend on it.

Example:

```text
unset network-object office-admin
```

```text
ERROR:
Network Object 'office-admin' is still referenced.

References:
  Remote Access: block-partner
  Internet Access: example-rule

No changes were applied.
```

The same reference-safe principle applies to:

```text
Network Objects / Groups
Service Objects / Groups
Permission Objects / Groups
AI Identities
Managed Hosts when referenced as Network Objects
```

References must be removed or changed first.

---

# 46. Managed Host removal

Server-side Managed Host removal:

```text
unset managed-host <HOST>
```

is reference-safe.

If policy references exist, removal is rejected.

When removal is allowed, DRLink cleans up server-side trust/inventory state and owned endpoint reservations associated with removed Agent-owned Remote Services.

The operation must show impact before destructive cleanup.

---

# 47. Agent local lifecycle

Agent Host local commands:

```text
show status
show agent

show remote-services
show remote-service <NAME>

set remote-service <NAME>
unset remote-service <NAME>

system info
system pause
system resume
system restart

system autostart enable
system autostart disable

system update product
system update engine

test configuration <FILE|->

system export configuration <FILE>
system diff configuration <FILE|->
system apply configuration <FILE|->

system diagnostics
system support-bundle
system version
system uninstall
```

`system uninstall` of the active product role must exit the interactive REPL
cleanly after successful removal (no further backend invocation on the deleted
install). User-facing diagnostics and support output label the role as
`Agent Host` (not `Client`). Development builds present version identity as
`2.4.0-dev+g<shortsha>` while preserving the exact 40-character Source HEAD
separately. Bundle SHA256 reports a real digest when known, otherwise
`not applicable` (never ambiguous `unknown`). Doctor recommended actions must
be public, role-correct commands that parse (for Agent Host frpc drift:
`sudo drlink system synchronize`).

The Server does not remotely execute these lifecycle mutations through the Server CLI.

---

# 48. Wrong CLI context errors

If a Server command is entered on an Agent Host:

```text
set remote-access block-partner
```

Agent result:

```text
ERROR:
Remote Access policy is managed on the DRLink Server.

Run this command on the DRLink Server.

No changes were applied.
```

If an Agent-local Remote Service mutation is entered on the Server:

```text
set remote-service ssh-access
```

Server result:

```text
ERROR:
Remote Service is managed from the DRLink Agent Host.

Run this command on the Agent Host that will own the Remote Service.

No changes were applied.
```

A role error should not be reduced to an unexplained `Unknown command`.

---

# 49. Server CLI reference

## 49.1 Show

```text
show status

show managed-hosts
show managed-host <HOST>
show managed-host <HOST> agent
show managed-host <HOST> addresses
show managed-host <HOST> remote-services

show enrollments
show enrollment <ENROLLMENT>

show network-objects
show network-object <OBJECT>
show network-object <OBJECT> references

show network-groups
show network-group <GROUP>
show network-group <GROUP> references

show service-objects
show service-object <SERVICE>
show service-object <SERVICE> references

show service-groups
show service-group <GROUP>
show service-group <GROUP> references

show remote-access
show remote-access <RULE>

show internet-access
show internet-access <RULE>

show ai-identities
show ai-identity <IDENTITY>

show permission-objects
show permission-object <PERMISSION>

show permission-groups
show permission-group <GROUP>

show ai-access
show ai-access <RULE>

show ai-access-log
show ai-access-log identity <IDENTITY>
show ai-access-log destination <DESTINATION>
show ai-access-log permission <PERMISSION>
```

---

## 49.2 Set

```text
set enrollment zero-touch
set enrollment manual
set enrollment bulk

set network-object <OBJECT>
set network-group <GROUP>

set service-object <SERVICE>
set service-group <GROUP>

set remote-access <RULE>
set remote-access enabled
set remote-access disabled

set internet-access <RULE>
set internet-access enabled
set internet-access disabled

set ai-identity <IDENTITY>

set permission-object <PERMISSION>
set permission-group <GROUP>

set ai-access <RULE>
set ai-access enabled
set ai-access disabled
```

Human invocation enters Guided Create/Edit unless a complete one-shot form is supplied.

---

## 49.3 Unset

```text
unset managed-host <HOST>
unset enrollment <ENROLLMENT>

unset network-object <OBJECT>
unset network-group <GROUP>

unset service-object <SERVICE>
unset service-group <GROUP>

unset remote-access <RULE>
unset remote-access policy

unset internet-access <RULE>
unset internet-access policy

unset ai-identity <IDENTITY>

unset permission-object <PERMISSION>
unset permission-group <GROUP>

unset ai-access <RULE>
unset ai-access policy
```

---

## 49.4 Test

```text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>

test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>

test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>

test configuration <FILE|->
```

---

## 49.5 System

```text
system status
system version
system diagnostics
system audit

system revisions
system revision <REVISION>
system diff <REVISION_A> <REVISION_B>
system rollback <REVISION>

system backup
system restore <FILE>

system export configuration <FILE>

system diff configuration <FILE|->
system apply configuration <FILE|->

system certificate
system update
system support-bundle
system uninstall
```

---

# 50. Server main menu

```text
Data Relay Link
├── 1. Managed Hosts
│   ├── List Managed Hosts
│   ├── Connect New Host
│   ├── Manage Host
│   └── Enrollments
│
├── 2. Network Objects
│   ├── Network Objects
│   └── Network Groups
│
├── 3. Service Objects
│   ├── Service Objects
│   └── Service Groups
│
├── 4. Remote Access
│   ├── Rules
│   └── Test / Explain
│
├── 5. Internet Access
│   ├── Rules
│   └── Test / Explain
│
├── 6. AI Access
│   ├── Connect AI / AI Identities
│   ├── Permission Objects
│   ├── Permission Groups
│   ├── Rules
│   ├── Access Log
│   └── Test / Explain
│
├── 7. System
├── 8. Help
└── 9. Exit
```

---

# 51. Agent Host local menu

```text
Data Relay Link — Agent Host
├── 1. Remote Services
│   ├── List Remote Services
│   ├── Create Remote Service
│   └── Manage Remote Service
│
├── 2. Agent
│   ├── Pause
│   ├── Resume
│   ├── Restart
│   └── Autostart
│
├── 3. Configuration
│   ├── Test Configuration
│   ├── Diff Configuration
│   ├── Apply Configuration
│   └── Export Configuration
│
├── 4. System
│   ├── Status
│   ├── Connection Information
│   ├── Diagnostics
│   ├── Support Bundle
│   ├── Version Information
│   ├── Updates
│   │   ├── Update Data Relay Link
│   │   └── Update Relay Engine
│   └── Uninstall Data Relay Link
│
├── 5. Help
└── 6. Exit
```

Server and Agent Host CLIs use the same public verbs, capitalization, System
organization, Help behavior, error contract, and discovery model. A supported
installation operates in exactly one public CLI role:

```text
Role: DRLink Server
```

or:

```text
Role: Agent Host
```

Dual-role / combined Server+Agent CLI mode is out of scope and unsupported in
v2.4. Do not present a hybrid hierarchy that mixes Server and Agent mutation
domains.

The initial screen and `show status` should identify the role clearly.
---

# 52. AI-assisted configuration principles

AI is a configuration assistant, not a separate configuration plane.

Two workflows exist.

```text
A. One Resource
→ one complete one-shot CLI command
→ copy / paste

B. Multiple dependent Resources
→ ConfigurationBundle
→ file or stdin
→ test / diff / apply
```

Human Wizard, AI one-shot, and ConfigurationBundle must converge to the same Change Plan and final authoritative state.

---

# 53. AI one-shot: complete command rule

AI should not generate a chain of incomplete mutation commands.

For a new Resource, required fields must be complete in one command.

Example:

```text
set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled
```

Example Internet Access:

```text
set internet-access github-https mode whitelist source office-network destination github service https enabled
```

Example AI Access after AI Identity and Permission Object already exist:

```text
set ai-access claude-prod mode whitelist source claude destination production-servers permission read-only enabled
```

If the Resource already exists, only explicitly supplied fields change.

Omitted fields retain their existing value.

Example:

```text
set remote-access block-partner disabled
```

changes only the Rule enabled state.

---

# 54. One-shot new Resource completeness

A new Resource must not be partially created.

Example incomplete Rule:

```text
set remote-access admin-ssh source office-admin destination ubuntu-prod service ssh
```

If enabled/disabled is required:

```text
ERROR:
Remote Access rule is incomplete.

Missing:
  enabled|disabled

No changes were applied.
```

When no Policy Mode exists, `mode blacklist|whitelist` is also required for a first one-shot Rule.

---

# 55. Missing dependency handling

AI one-shot must not silently create missing dependencies.

Example:

```text
set remote-access block-admin mode blacklist source office-admin destination ubuntu-prod service ssh enabled
```

If `office-admin` does not exist:

```text
ERROR:
Required Network Object 'office-admin' does not exist.

No changes were applied.

Create the required Network Object first,
or use a ConfigurationBundle to create the dependencies and Rule together.
```

---

# 56. Public names, not hidden IDs

AI and users operate with public names.

Example:

```text
destination ubuntu-prod
service ssh
permission read-only
```

Commands do not require database UUIDs.

Name duplication that would make a public selector ambiguous is rejected as normal validation.

Reserved command tokens such as `enabled`, `disabled`, and `policy` cannot be used where they would collide with command grammar.

---

# 57. ConfigurationBundle purpose

A ConfigurationBundle represents several dependent configuration changes as one Change Plan.

It is input to DRLink, not a second authoritative database.

```text
ConfigurationBundle
→ Parse
→ Validate
→ Resolve references
→ Build Change Plan
→ Calculate diff
→ Calculate security impact
→ Confirm if required
→ Atomic apply
→ Runtime activation
→ Verification
→ Authoritative DRLink state
```

---

# 58. ConfigurationBundle atomicity boundary

Atomicity is scoped to the current CLI context.

```text
Server ConfigurationBundle
→ atomic within Server authoritative configuration

Agent ConfigurationBundle
→ atomic within that Agent Host
```

A single atomic Bundle does not span the Server and one or more Agent Hosts.

Example request:

> Create SSH Remote Service on ubuntu-prod and allow office-admin to access it.

AI should split this into:

```text
Agent Host operation / Agent ConfigurationBundle
→ create Remote Service

Server operation / Server ConfigurationBundle or one-shot command
→ create Remote Access policy/rule
```

Each context is independently validated and applied.

---

# 59. Server ConfigurationBundle scope

A Server ConfigurationBundle may manage Server-authoritative configuration, including:

```text
Network Objects
Network Groups
Service Objects
Service Groups
Permission Objects
Permission Groups
Remote Access policy/rules
Internet Access policy/rules
AI Access policy/rules
```

It may reference existing Managed Hosts and authenticated AI Identities.

Enrollment and authentication are lifecycle workflows and are not bypassed merely by declaring a name in a Bundle.

---

# 60. Agent ConfigurationBundle scope

An Agent ConfigurationBundle manages the current Agent Host's local configuration.

Primary configuration item:

```text
Remote Services
```

It does not mutate Server Access Policies.

Example intent:

```text
On branch-gateway:
  create internal-db-postgres
  destination internal-db
  service postgres
```

This can be represented and applied atomically within that Agent Host.

---

# 61. Canonical ConfigurationBundle YAML

The following is the canonical v2.4 ConfigurationBundle contract.

General rules:

```text
configurationBundle.context
→ server | agent

state omitted
→ present/update semantics

state: absent
→ explicit deletion

resource omitted
→ UNCHANGED

field omitted on an existing resource
→ UNCHANGED

list field explicitly supplied
→ exact desired list for that resource

same desired state
→ NO CHANGE
```

A Bundle is a patch/desired-change document, not a complete replacement of every DRLink resource.

`state: absent` expresses deletion/reset intent and cannot be combined with fields that describe the desired present-state contents of the same resource.

Invalid example:

```yaml
networkObjects:
  - name: old-network
    state: absent
    type: cidr
    value: 10.0.0.0/8
```

Result:

```text
ERROR:
Resource 'old-network' declares state: absent and present-state fields.

No changes were applied.
```

---

## 61.1 Complete Server Bundle shape

A Server Bundle may contain any subset of the following sections.

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: office-admin
      type: ip
      value: 203.0.113.10

    - name: corp-network
      type: cidr
      value: 10.10.0.0/16

    - name: github
      type: fqdn
      value: github.com

    - name: old-network-object
      state: absent

  networkGroups:
    - name: approved-admins
      members:
        - office-admin
        - vpn-admin

  serviceObjects:
    - name: ssh
      type: tcp
      port: 22

    - name: dns-udp
      type: udp
      port: 53

    - name: legacy-db
      type: fixed-tcp
      port: 1521

  serviceGroups:
    - name: web-services
      members:
        - http
        - https

  permissionObjects:
    - name: read-only
      permissions:
        - host-info
        - process-read
        - file-read

  permissionGroups:
    - name: operators
      members:
        - read-only
        - operator

  remoteAccess:
    mode: blacklist
    enforcement: enabled
    rules:
      - name: block-partner-ssh
        source: partner-office
        destination: ubuntu-prod
        service: ssh
        enabled: true

      - name: obsolete-rule
        state: absent

  internetAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: github-https
        source: ubuntu-prod
        destination: github
        service: https
        enabled: true

  aiAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: claude-prod-read
        source: claude
        destination: production-servers
        permission: read-only
        enabled: true
```

Managed Hosts and authenticated AI Identities are referenced by public name but are not created by a Server ConfigurationBundle.

Enrollment and AI authentication remain their respective lifecycle workflows.

---

## 61.2 Server policy semantics in a Bundle

For an unconfigured policy, creating Rules requires `mode`.

Example:

```yaml
remoteAccess:
  mode: blacklist
  enforcement: enabled
  rules:
    - name: block-partner
      source: partner-office
      destination: ubuntu-prod
      service: ssh
      enabled: true
```

For an already configured policy:

```text
mode omitted
→ existing mode retained

enforcement omitted
→ existing enforcement retained

rules omitted
→ existing Rules retained

a Rule omitted from rules[]
→ that Rule is retained

a Rule with state: absent
→ that Rule is deleted
```

A conflicting mode is rejected.

Policy reset is explicit:

```yaml
configurationBundle:
  context: server

  remoteAccess:
    state: absent
```

This means:

```text
remove Remote Access Mode
remove all Remote Access Rules
return Remote Access to initial No Policy / ALLOW state
```

Equivalent forms apply to:

```text
internetAccess
aiAccess
```

Policy Reset never implicitly removes AI Identity authentication.

---

## 61.3 Group and permission list updates

When `members` or `permissions` is explicitly supplied, it is the exact desired list for that resource.

Example:

```yaml
networkGroups:
  - name: approved-admins
    members:
      - office-admin
      - vpn-admin
```

If `approved-admins` previously also contained `partner-admin`, applying this Bundle removes `partner-admin` from that Group.

If `members` is omitted on an existing Group, membership is unchanged.

The same rule applies to:

```text
Network Group.members
Service Group.members
Permission Group.members
Permission Object.permissions
```

---

## 61.4 Internet Access Managed Host example

A Managed Host is valid as an Internet Access source.

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: github
      type: fqdn
      value: github.com

  serviceObjects:
    - name: https
      type: tcp
      port: 443

  internetAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: ubuntu-prod-github
        source: ubuntu-prod
        destination: github
        service: https
        enabled: true
```

A Managed Host is invalid as an Internet Access destination.

---

## 61.5 Complete Agent Bundle shape

An Agent Bundle manages only the current Agent Host's Remote Services.

```yaml
configurationBundle:
  context: agent

  remoteServices:
    - name: ssh-access
      destination: this-host
      service: ssh
      enabled: true

    - name: internal-db-postgres
      destination: internal-db
      service: postgres
      enabled: true

    - name: old-service
      state: absent
```

Rules:

```text
current Agent Host
→ implicit owner

destination != this-host
→ current Agent Host is the Relay Host

service
→ one TCP or Fixed TCP Service Object

UDP Service Object
→ rejected

state: absent
→ delete Remote Service and return its endpoint reservation

existing Remote Service field omitted
→ unchanged
```

A Server context Bundle cannot contain `remoteServices`.

An Agent context Bundle cannot contain Server Objects/Groups/Access Policies.

Context mismatch is rejected before mutation.

---

## 61.6 Agent Bundle while Server is temporarily unreachable

Agent Bundle validation and local configuration mutation may proceed using synchronized local Object metadata.

Existing endpoint reservations are preserved.

For a new Remote Service that needs a Server-assigned endpoint while the Server is unreachable:

```text
configuration saved
→ DEGRADED
→ Endpoint: Pending allocation
```

After reconnect:

```text
synchronize
→ allocate endpoint
→ activate
→ verify
→ HEALTHY
```

A missing/unresolvable dependency in the local synchronized catalog is still a validation error.

If locally cached metadata was valid when an offline edit was accepted but the Server authoritative catalog changed before reconnect, synchronization revalidates the references.

If a required dependency is no longer valid:

```text
Remote Service configuration
→ retained for operator visibility

Status
→ DEGRADED

Runtime activation
→ not performed
```

The reason must identify the missing or invalid dependency. DRLink does not silently retarget, delete, or recreate the Remote Service.

The operator can correct or remove the Remote Service after inspecting the reconciliation error.

---

# 62. Bundle update and delete semantics

Deletion uses `state: absent` on the specific resource or policy.

Examples:

Delete a Network Object:

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: old-partner
      state: absent
```

Delete one Rule while preserving the Policy Mode and other Rules:

```yaml
configurationBundle:
  context: server

  remoteAccess:
    rules:
      - name: old-rule
        state: absent
```

Reset the whole Policy:

```yaml
configurationBundle:
  context: server

  remoteAccess:
    state: absent
```

Delete an Agent Remote Service:

```yaml
configurationBundle:
  context: agent

  remoteServices:
    - name: old-service
      state: absent
```

All deletion remains subject to reference and impact validation.

If a referenced resource cannot be deleted:

```text
ERROR:
Network Object 'old-partner' is still referenced.

No changes were applied.
```

---

# 63. Bundle ordering

Bundle declaration order does not control dependency resolution.

For example, a Rule may appear before the Object it references in the YAML document.

DRLink performs:

```text
whole-document parse
→ whole-document reference resolution
→ whole-document validation
→ Change Plan
```

before mutation.

AI does not need to know internal application order.

---

# 64. Bundle file workflow

File workflow:

```text
test configuration drlink-config.yaml
system diff configuration drlink-config.yaml
system apply configuration drlink-config.yaml
```

`test`:

```text
Syntax
Schema
Required fields
References
Policy validity
Context validity
```

No state changes.

`diff`:

```text
CREATE
UPDATE
DELETE
NO CHANGE
Security impact
```

No state changes.

`apply`:

```text
Re-parse
Re-validate
Re-resolve
Re-diff against current authoritative state
Recalculate security impact
Confirm when required
Atomic apply
Runtime activation
Verification
```

---

# 65. stdin copy/paste workflow

Use `-` for stdin:

```text
test configuration -
system diff configuration -
system apply configuration -
```

The CLI must display the termination instruction before accepting input.

Canonical interactive UX:

```text
Paste ConfigurationBundle YAML below.
Finish with a line containing only:
:end
```

Example:

```text
drlink> test configuration -

Paste ConfigurationBundle YAML below.
Finish with a line containing only:
:end

configurationBundle:
  context: server
  ...
:end
```

`:end` is the CLI input terminator and is not part of YAML.

---

# 66. AI output for ConfigurationBundle

When a user asks AI for a ConfigurationBundle intended for direct paste, AI should output raw Bundle YAML only.

It should not include prose inside the pasted block.

If the user accidentally pastes Markdown fences or explanatory prose into the DRLink configuration input, DRLink must fail safely.

Example:

```text
ERROR:
Configuration input is not valid ConfigurationBundle YAML.

Unexpected content before the Bundle.

No changes were applied.
```

DRLink must not silently apply a valid-looking subset of a malformed pasted response.

---

# 67. test / diff / apply independence

Each command validates its own input.

Example:

```text
test  → Bundle A
diff  → Bundle A
apply → Bundle B
```

`apply` must fully validate Bundle B.

A previous successful `test` or `diff` is not an approval token.

---

# 68. ConfigurationBundle idempotency

Reapplying the same desired state:

```text
NO CHANGE
Configuration already matches the requested state.
```

No unnecessary side effects:

```text
No revision increase solely for NO CHANGE
No Resource recreation
No endpoint-port reallocation
No runtime restart
No audit noise beyond an optional no-change invocation record
```

Fixed TCP endpoint ports remain unchanged.

Remote Service endpoint ports remain unchanged.

---

# 69. Export → AI → Reapply

Server export:

```text
system export configuration drlink-config.yaml
```

Workflow:

```text
DRLink
→ export
→ user gives exported configuration to AI
→ AI modifies public configuration
→ test
→ diff
→ review
→ apply
```

An omitted Resource is not deleted.

A delete must be explicit.

`system export configuration <FILE>` produces a valid ConfigurationBundle for the current CLI context:

```text
Server CLI
→ context: server

Agent CLI
→ context: agent
```

The exported document uses the same canonical schema accepted by `test`, `diff`, and `apply`.

Runtime-only values such as current health, temporary reachability failures, and allocated endpoint status are not treated as desired-configuration fields.

---

# 70. Secret handling

Configuration export must not expose real secrets.

Examples:

```text
OAuth tokens
Bearer tokens
Enrollment secrets
Private keys
Credentials
```

Secret values are excluded from exported configuration.

If a secret field is omitted from an imported Bundle:

```text
existing secret
→ unchanged
```

A display placeholder such as `REDACTED` must never be treated as a real new secret.

---

# 71. Runtime activation and atomic Apply

Successful authoritative mutation is not enough to report Apply success.

The required sequence is:

```text
Parse
→ Validate
→ Resolve
→ Change Plan
→ Security Impact
→ Confirmation
→ Candidate authoritative transaction
→ Runtime generation
→ Activation
→ Verification
→ SUCCESS
```

If critical runtime activation or verification fails, DRLink restores the previous authoritative and runtime state.

Example:

```text
ERROR:
Runtime activation failed.

Previous configuration was restored.
No configuration changes remain active.
```

A valid-but-unreachable Relay destination is not a critical activation failure; it creates a `DEGRADED` Remote Service as defined earlier.

A temporarily unreachable DRLink Server during an Agent-local Remote Service apply is also not a critical configuration failure when local validation succeeds. The configuration is retained as `DEGRADED`; a new endpoint may remain `Pending allocation` until synchronization resumes.

If automatic rollback itself cannot fully restore the previous state:

```text
ERROR:
Apply failed and automatic rollback was not fully successful.

The current runtime state may require operator attention.

Run:
  system diagnostics
```

DRLink must not falsely report `No changes were applied` when rollback was incomplete.

---

# 72. Concurrency

`apply` evaluates the current authoritative state at execution time.

If state changed after a previous `test` or `diff`:

```text
Apply
→ read current state
→ recalculate references
→ recalculate diff
→ recalculate security impact
→ show updated result/confirmation when required
→ apply
```

A stale earlier diff is never blindly applied.

---

# 72.1 Rollback and restore use the same safety pipeline

`system rollback` and `system restore` are configuration mutations and therefore use the same safety contract as normal Apply.

They must perform, as applicable:

```text
resolve target configuration
→ validate
→ calculate diff
→ calculate security impact
→ confirmation when required
→ authoritative transaction
→ runtime activation
→ verification
→ rollback-on-failure
```

A rollback or restore that broadens access must not bypass security-impact confirmation.

---

# 73. Security-impact confirmation

Changes that broaden access should be called out clearly.

Examples:

```text
Deleting the last BLACKLIST blocking Rule
Disabling policy enforcement
Resetting a restrictive policy
Removing a blocking condition
```

Example:

```text
WARNING:
This change broadens Remote Access.

Effective result after Apply:
  ALLOW ALL

Continue? [y/N]
```

A WHITELIST change that removes the last enabled allow Rule should also clearly warn that effective access becomes DENY ALL, even though this is a restriction rather than a broadening.

---

# 74. AI Access Log

Commands:

```text
show ai-access-log
show ai-access-log identity <IDENTITY>
show ai-access-log destination <DESTINATION>
show ai-access-log permission <PERMISSION>
```

Each useful log entry should expose at least:

```text
Timestamp
AI Identity
Destination
Permission
Result
```

Example:

```text
TIME                     IDENTITY   DESTINATION     PERMISSION   RESULT
2026-09-18T00:10:31+09   claude    ubuntu-prod    read-only    ALLOW
```

Where useful, matched policy/rule details may be shown to support troubleshooting.

---

# 75. Error contract

User-facing errors should answer four questions:

```text
1. What failed?
2. What was expected?
3. Were any changes applied?
4. What should the user do next?
```

Example:

```text
ERROR:
Destination 'ubuntu-prod-x' was not found.

Expected:
  Network Object
  Network Group

No changes were applied.

Use:
  show network-objects
  show network-groups
```

Raw backend tracebacks are not an acceptable primary user-facing error.

---

# 76. Name and reserved-token validation

Names are public selectors.

DRLink rejects:

```text
duplicate names that make selection ambiguous
reserved command tokens used where they conflict with grammar
```

Examples of reserved tokens in Access Policy command positions include:

```text
enabled
disabled
policy
```

This is ordinary input validation.

---

# 77. Scenario — first install and first run

User:

```text
drlink
```

Expected:

```text
Role: DRLink Server

No access restrictions are currently configured.
Access is allowed by default.
```

User understands:

```text
Remote Access
Internet Access
AI Access

Blacklist = define blocks
Whitelist = define allows
```

No Rule is required merely to make the product initially usable.

---

# 78. Scenario — Zero-Touch and direct SSH Remote Service

Server:

```text
set enrollment zero-touch
```

When a public DNS hostname is configured, Enrollment HTTPS and Zero-Touch
bootstrap URLs use that hostname (public IP may still be shown as fallback).
The operator-facing Zero-Touch install command is a short HTTPS launcher
(`curl … https://<host>/i/<ticket> | sudo bash` or equivalent) that preserves
private-CA fingerprint verification and one-time ticket semantics inside the
maintained bootstrap artifact—not a long inline shell program.

SSH connection-example username is optional metadata for the hint only; it is
not required for Agent install/enrollment. Prefer a verified local account, or
show `<username>` rather than inventing an unverified account name.

A Zero-Touch flow that declares an initial Remote Service must complete
allocation → runtime generation → activation before claiming the service is
connected. Preferred endpoint presentation uses the configured public hostname
and a stable reserved port for that Remote Service identity.

After registration:

```text
Managed Host connected successfully.

Host  : ubuntu-prod
Agent : Connected
```

On `ubuntu-prod` (when not already created by Zero-Touch initial service):

```text
set remote-service ssh-access
```

```text
Destination : This Host
Service     : ssh
Enabled     : Yes
```

Result:

```text
Remote Service activated.

Status   : HEALTHY
Endpoint : remote.example:6101

Connection:
  ssh -p 6101 <username>@remote.example
```

No Remote Access Policy exists yet:

```text
Effective Remote Access = ALLOW
```

Therefore the already activated Remote Service is usable.

---

# 79. Scenario — Remote Access BLACKLIST

Goal:

> Block partner-office from SSH to ubuntu-prod while leaving unmatched access allowed.

Server:

```text
set remote-access block-partner-ssh
```

First Rule:

```text
Choose policy mode:
→ Blacklist
```

Rule:

```text
Source      : partner-office
Destination : ubuntu-prod
Service     : ssh
Enabled     : Yes
```

Review:

```text
Effect:
Matching access will be BLOCKED.
All other access remains ALLOWED.
```

Test:

```text
test remote-access source partner-office destination ubuntu-prod service ssh
```

Result:

```text
DENY
```

Different source:

```text
test remote-access source office-admin destination ubuntu-prod service ssh
```

Result:

```text
ALLOW
```

---

# 80. Scenario — WHITELIST reconstruction

Existing Remote Access is BLACKLIST.

User wants a WHITELIST instead.

The mode is not directly flipped.

```text
system export configuration remote-before.yaml
unset remote-access policy
```

Then create the first Rule:

```text
set remote-access office-ssh
```

Select:

```text
Whitelist
```

Configure:

```text
Source      : office-admin
Destination : ubuntu-prod
Service     : ssh
Enabled     : Yes
```

Result:

```text
office-admin match → ALLOW
all unmatched      → DENY
```

---

# 81. Scenario — Policy troubleshooting without deleting Rules

A WHITELIST appears to be blocking a connection.

User temporarily disables enforcement:

```text
set remote-access disabled
```

Expected:

```text
Mode        : WHITELIST
Enforcement : DISABLED
Effective   : ALLOW ALL

Saved rules remain unchanged.
```

After testing:

```text
set remote-access enabled
```

The original WHITELIST and Rules return immediately.

---

# 82. Scenario — inline Object creation then Cancel

User:

```text
set remote-access block-temp
```

During Source selection:

```text
+ Create Network Object
```

Draft Object:

```text
temp-office
IP
203.0.113.50
```

User later selects:

```text
Cancel
```

Expected:

```text
No changes were applied.
```

Verification:

```text
show network-object temp-office
```

Expected:

```text
Not found
```

The draft Object did not leak into authoritative state.

---

# 83. Scenario — Relay Host configured before target is reachable

On `branch-gateway`:

```text
set remote-service internal-db-postgres
```

```text
Destination : internal-db
Service     : postgres
Enabled     : Yes
```

The configuration is structurally valid but `internal-db:5432` is currently unreachable.

Expected:

```text
Remote Service created.

Status   : DEGRADED
Endpoint : drlink.example:6102

Reason:
  Destination is currently unreachable from Relay Host.
```

Later the network/firewall becomes ready.

Expected automatic transition:

```text
DEGRADED
→ HEALTHY
```

Endpoint stays:

```text
drlink.example:6102
```

---

# 84. Scenario — Fixed TCP Remote Service

Server:

```text
set service-object legacy-db
```

Wizard:

```text
Type : Fixed TCP
Port : 1521
```

On `branch-gateway`:

```text
set remote-service legacy-db-access
```

```text
Destination : internal-db
Service     : legacy-db
Enabled     : Yes
```

Expected:

```text
Endpoint : drlink.example:6201
Status   : HEALTHY
```

The external port is allocated from the Fixed TCP pool.

The user never chooses `6201`.

Disable:

```text
set remote-service legacy-db-access
→ Disable
```

Expected:

```text
Status       : DISABLED
Reserved Port: 6201
```

Re-enable:

```text
→ same 6201
```

Delete:

```text
unset remote-service legacy-db-access
```

Expected:

```text
6201 returned to Fixed TCP pool
```

---

# 85. Scenario — cross-pool edit rejected

Existing:

```text
Remote Service : ssh-access
Service        : ssh
Endpoint       : drlink.example:6101
```

User edits Service to:

```text
legacy-db
Type: Fixed TCP
```

Expected:

```text
ERROR:
The Service type cannot be changed between standard TCP and Fixed TCP
for an existing Remote Service.

Delete and recreate the Remote Service.

No changes were applied.
```

---

# 85.1 Scenario — UDP Service Object rejected by Remote Service

Server contains:

```text
dns-udp
  UDP/53
```

On an Agent Host:

```text
set remote-service dns-access destination this-host service dns-udp enabled
```

Expected:

```text
ERROR:
Service Object 'dns-udp' uses UDP.

Remote Service supports TCP and Fixed TCP services only.

No changes were applied.
```

The UDP Service Object itself remains valid for supported non-Remote-Service uses.

---

# 86. Scenario — Internet WHITELIST: GitHub HTTPS only

Server Objects:

```text
office-network
  CIDR
  203.0.113.0/24

github
  FQDN
  github.com

https
  TCP/443
```

First Rule:

```text
set internet-access github-https
```

Select:

```text
Whitelist
```

Rule:

```text
Source      : office-network
Destination : github
Service     : https
Enabled     : Yes
```

Effective policy:

```text
match    → ALLOW
no match → DENY
```

The WHITELIST default handles all unmatched traffic.

---

# 87. Scenario — Internet Access Managed Host source

A Managed Host may be used directly as an Internet Access source.

Example:

```text
set internet-access ubuntu-prod-github mode whitelist source ubuntu-prod destination github service https enabled
```

Expected:

```text
source ubuntu-prod
→ valid

destination github
→ valid
```

A Managed Host cannot be used as the Internet Access destination.

Example:

```text
set internet-access invalid-rule source office-network destination ubuntu-prod service https enabled
```

Expected:

```text
ERROR:
Managed Host 'ubuntu-prod' cannot be used as an Internet Access destination.

Use an IP, CIDR, or FQDN Network Object as the destination.

No changes were applied.
```

A destination Network Group is likewise rejected if it contains any Managed Host.

---

# 88. Scenario — AI Identity and AI Access

Server:

```text
set ai-identity claude
```

Interactive authentication completes:

```text
AI Identity : claude
Status      : VERIFIED
```

Create Permission Object:

```text
set permission-object read-only
```

Permissions:

```text
host-info
process-read
file-read
```

Create first AI Access Rule:

```text
set ai-access claude-prod
```

Choose:

```text
Whitelist
```

Rule:

```text
Source      : claude
Destination : production-servers
Permission  : read-only
Enabled     : Yes
```

Effective:

```text
authenticated claude + matching destination/permission
→ ALLOW

unmatched AI Access request
→ DENY
```

Unauthenticated access is not made valid by policy mode.

---

# 89. Scenario — AI Access enforcement temporarily disabled

User:

```text
set ai-access disabled
```

Expected:

```text
Policy Mode      : WHITELIST
Policy Enforcement: DISABLED
Effective Policy : ALLOW ALL
```

But:

```text
AI authentication
→ still required
```

Re-enable:

```text
set ai-access enabled
```

Saved Rules become effective again.

---

# 90. Scenario — AI one-shot first Rule

User asks AI:

> Create a DRLink command that allows only office-network to access github over HTTPS.

AI knows this is the first Internet Access Rule and generates:

```text
set internet-access github-https mode whitelist source office-network destination github service https enabled
```

DRLink:

```text
Parse
Validate all references
Validate complete first-policy mode
Review security impact
Atomic apply
```

No partial Resource is created.

---

# 91. Scenario — AI one-shot missing Object

AI generates:

```text
set remote-access block-admin mode blacklist source office-admin destination ubuntu-prod service ssh enabled
```

`office-admin` does not exist.

Expected:

```text
ERROR:
Required Network Object 'office-admin' does not exist.

No changes were applied.

Create the required Network Object first,
or use a ConfigurationBundle to create the dependencies and Rule together.
```

The user can paste this error back to AI to regenerate a valid configuration.

---

# 92. Scenario — Server ConfigurationBundle multi-resource

User asks AI:

> From office-network, allow only github.com over HTTPS.

AI returns:

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: office-network
      type: cidr
      value: 203.0.113.0/24

    - name: github
      type: fqdn
      value: github.com

  serviceObjects:
    - name: https
      type: tcp
      port: 443

  internetAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: github-https
        source: office-network
        destination: github
        service: https
        enabled: true
```

User:

```text
test configuration -
```

Paste YAML, then:

```text
:end
```

Expected:

```text
VALID

Planned changes:
  CREATE Network Object office-network
  CREATE Network Object github
  CREATE Service Object https
  CONFIGURE Internet Access WHITELIST
  CREATE Internet Access Rule github-https

No changes were applied.
```

Then:

```text
system diff configuration -
```

Then:

```text
system apply configuration -
```

Apply performs full validation again.

---

# 93. Scenario — Agent ConfigurationBundle

On `branch-gateway`, AI generates:

```yaml
configurationBundle:
  context: agent

  remoteServices:
    - name: internal-db-postgres
      destination: internal-db
      service: postgres
      enabled: true
```

The Agent validates:

```text
Destination reference
Service reference from Server
Local Agent role/context
Port availability
Runtime activation
```

If the destination is currently unreachable but all configuration is valid:

```text
Apply succeeds
Remote Service status = DEGRADED
Endpoint reservation retained
```

---

# 94. Scenario — cross-context AI request

User asks AI:

> On ubuntu-prod create SSH Remote Service and allow only office-admin to use it.

AI must not pretend this is one distributed atomic Bundle.

AI produces two context-specific operations.

Agent Host (`ubuntu-prod`):

```text
set remote-service ssh-access destination this-host service ssh enabled
```

Server:

```text
set remote-access office-ssh mode whitelist source office-admin destination ubuntu-prod service ssh enabled
```

Each context applies independently.

---

# 95. Scenario — Bundle failure at final Resource

Bundle contains:

```text
valid Network Object
valid Service Object
invalid Rule reference
```

Expected:

```text
ERROR:
Reference validation failed.

No changes were applied.
```

Verification:

```text
The Network Object was not created.
The Service Object was not created.
```

---

# 96. Scenario — same Bundle reapply

Apply Bundle once:

```text
SUCCESS
```

Apply same desired state again:

```text
NO CHANGE
Configuration already matches the requested state.
```

Expected:

```text
No endpoint port changes
No Fixed TCP port changes
No unnecessary runtime restart
No Resource recreation
```

---

# 97. Scenario — test A, apply B

User tests Bundle A:

```text
test configuration -
```

Later accidentally pastes Bundle B into:

```text
system apply configuration -
```

Expected:

```text
Bundle B is independently parsed and validated.
Current-state diff is recalculated.
Security impact is recalculated.
Confirmation is based on Bundle B.
```

A previous successful test of Bundle A has no authority over Bundle B.

---

# 98. Scenario — Export → AI → Reapply

User:

```text
system export configuration current.yaml
```

The export contains no real authentication secrets.

User asks AI:

> Add a Remote Access blocking Rule for partner-office.

AI edits only public configuration.

User:

```text
test configuration modified.yaml
system diff configuration modified.yaml
system apply configuration modified.yaml
```

Resources not present in the requested change remain unchanged unless explicitly marked for deletion.

---

# 99. Scenario — referenced Object deletion

User:

```text
unset service-object ssh
```

But `ssh` is referenced by Remote Access Rules and Remote Services.

Expected:

```text
ERROR:
Service Object 'ssh' is still referenced.

References:
  Remote Access: office-ssh
  Remote Service: ubuntu-prod / ssh-access

No changes were applied.
```

The user must remove/change references first.

---

# 100. Scenario — Policy last Rule behavior

BLACKLIST:

```text
1 Rule
→ delete it
→ BLACKLIST remains
→ 0 Rules
→ Effective ALLOW ALL
```

WHITELIST:

```text
1 Rule
→ delete it
→ WHITELIST remains
→ 0 Rules
→ Effective DENY ALL
```

To return to the original no-policy state:

```text
unset <access-policy> policy
```

---

# 101. Scenario — runtime activation failure and rollback

A Server Bundle passes schema and reference validation.

During activation:

```text
critical runtime bind/generation step fails
```

Expected:

```text
Apply fails.
Previous authoritative configuration restored.
Previous runtime restored.
```

Output:

```text
ERROR:
Runtime activation failed.

Previous configuration was restored.
No configuration changes remain active.
```

This differs from a Relay destination that is merely unreachable; that valid configuration becomes `DEGRADED`.

---

# 101.1 Scenario — create Remote Service while Server is unreachable

The Agent has synchronized metadata for:

```text
ssh
ubuntu-prod
```

The Server becomes temporarily unreachable.

On `ubuntu-prod`:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

Expected:

```text
Remote Service created.

Status   : DEGRADED
Endpoint : Pending allocation

Reason:
  DRLink Server is currently unreachable.
```

No configuration rollback occurs merely because endpoint allocation is temporarily unavailable.

After Server connectivity returns:

```text
synchronize
→ allocate endpoint
→ activate
→ HEALTHY
```

The operator does not need to recreate the Remote Service.

---

# 102. Scenario — Agent disconnect/reconnect

Existing:

```text
Remote Service : ssh-access
Endpoint       : drlink.example:6101
Status         : HEALTHY
```

Agent loses connectivity.

Expected:

```text
Status         : DEGRADED
Endpoint       : drlink.example:6101
Port reservation retained
```

Agent reconnects.

Expected:

```text
Status         : HEALTHY
Endpoint       : drlink.example:6101
```

No operator action required.

---

# 103. Scenario — Server/Agent role mistake

On Agent Host:

```text
set internet-access github-https
```

Expected:

```text
ERROR:
Internet Access policy is managed on the DRLink Server.

Run this command on the DRLink Server.

No changes were applied.
```

On Server:

```text
set remote-service ssh-access
```

Expected:

```text
ERROR:
Remote Service is managed from the DRLink Agent Host.

Run this command on the Agent Host that will own the Remote Service.

No changes were applied.
```

---

# 104. Operational invariants

The following invariants must hold across Human Wizard, AI one-shot, and ConfigurationBundle.

```text
Same intent
→ same policy semantics
→ same Change Plan
→ same final authoritative state
```

```text
Validation failure
→ no partial authoritative mutation
```

```text
Wizard Cancel
→ no draft Resources left behind
```

```text
No Policy
→ ALLOW
```

```text
BLACKLIST
→ match DENY
→ no match ALLOW
```

```text
WHITELIST
→ match ALLOW
→ no match DENY
```

```text
Policy Enforcement DISABLED
→ ALLOW ALL
→ saved Mode/Rules preserved
```

```text
Policy Reset
→ Mode removed
→ Rules removed
→ ALLOW
```

```text
Remote Service
→ connectivity lifecycle

Access Policy
→ authorization lifecycle
```

```text
DEGRADED
→ valid configuration with temporary runtime/reachability problem
```

```text
DISABLED
→ deliberate operator state
```

```text
Same Bundle reapply
→ NO CHANGE
```

```text
Secret omitted from import
→ existing secret unchanged
```

```text
Server Bundle
→ Server atomicity only

Agent Bundle
→ one Agent Host atomicity only
```

---

# 105. Implementation and test acceptance checklist

A v2.4 CLI implementation is conformant only if the following can all be demonstrated.

## First-use

- `drlink` clearly identifies Server vs Agent Host role.
- Initial access is understandable as ALLOW without requiring a Rule.
- Help/menu leads to Objects, Policies, Managed Hosts, and Agent functions correctly.

## Objects

- IP/CIDR/FQDN Network Objects create/edit/delete correctly.
- Managed Hosts work as Network Objects where allowed.
- `show network-objects` exposes Managed Hosts as type `Managed Host`, while Managed Host mutation remains under Managed Host lifecycle commands.
- Network Groups work without nested-group dependence.
- TCP/UDP/Fixed TCP Service Objects work at the Server Object layer.
- Remote Service accepts TCP and Fixed TCP only; UDP is rejected.
- Remote Access Rules reject UDP Service Objects and Service Groups containing UDP.
- Service Groups work.
- Permission Objects and Groups work.
- Reference-safe deletion prevents broken configuration.

## Policy

- First Human Rule selects BLACKLIST/WHITELIST.
- First AI one-shot Rule requires `mode`.
- Multiple matches behave deterministically without rule ordering.
- Last Rule deletion preserves Mode.
- Rule disable and Policy disable have different, correctly explained effects.
- Policy reset returns to initial ALLOW state.
- Direct Mode conversion is not performed.

## Remote Service

- Agent local `show/set/unset remote-service` works.
- Direct `This Host` flow works.
- Relay Host flow works without a separate Relay-specific configuration object.
- `HEALTHY / DEGRADED / DISABLED` transitions are correct.
- Offline create/edit can remain DEGRADED/Pending allocation and synchronize after reconnect.
- Offline Remote Service deletion eventually releases its Server-side endpoint reservation after reconnect.
- Endpoint/port survives restart/disconnect/disable.
- Delete returns the port.
- Fixed TCP uses a separate endpoint pool.
- Cross-pool Service edit is rejected.
- Server can inspect Remote Service state read-only.

## AI Identity / AI Access

- Interactive and automation authentication can bind an AI Identity.
- Policy evaluation occurs only after identity authentication.
- AI Access BLACKLIST/WHITELIST behaves like the other policy families.
- Policy disable does not remove authentication.
- AI Access Log supports identity/destination/permission filtering.

## AI CLI

- New one-shot Resources are complete and atomic.
- Existing one-shot edits preserve omitted fields.
- Missing dependencies are not auto-created.
- Errors are suitable for copy-back into AI.
- Public names are sufficient; hidden IDs are not required.

## ConfigurationBundle

- Server and Agent contexts are distinct.
- Agent CLI exposes `test configuration`, `system diff configuration`, `system apply configuration`, and `system export configuration`.
- No cross-context distributed atomic transaction is attempted.
- Server and Agent contexts both provide file and stdin ConfigurationBundle workflows.
- File and stdin workflows both work.
- `:end` terminates stdin paste mode.
- Bundle ordering does not control dependency resolution.
- Invalid final Resource leaves no earlier Resource behind.
- Same Bundle reapply produces `NO CHANGE`.
- `test`, `diff`, and `apply` independently validate input.
- Export omits secrets.
- Runtime activation failure restores previous state when rollback succeeds.
- Incomplete rollback is reported truthfully.

---

# 106. Quick-reference examples

## Block SSH from one source

Existing Remote Access mode is BLACKLIST:

```text
set remote-access block-partner-ssh source partner-office destination ubuntu-prod service ssh enabled
```

If this is the first Rule:

```text
set remote-access block-partner-ssh mode blacklist source partner-office destination ubuntu-prod service ssh enabled
```

---

## Allow only GitHub HTTPS

First Internet Access Rule:

```text
set internet-access github-https mode whitelist source office-network destination github service https enabled
```

---

## Create direct SSH Remote Service

On `ubuntu-prod`:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

---

## Create relayed PostgreSQL Remote Service

On `branch-gateway`:

```text
set remote-service internal-db-postgres destination internal-db service postgres enabled
```

---

## Create Fixed TCP service

On Server:

```text
set service-object legacy-db type fixed-tcp port 1521
```

On Relay Host:

```text
set remote-service legacy-db-access destination internal-db service legacy-db enabled
```

---

## Test Remote Access

```text
test remote-access source office-admin destination ubuntu-prod service ssh
```

---

## Temporarily disable Remote Access enforcement

```text
set remote-access disabled
```

Restore:

```text
set remote-access enabled
```

---

## Reset Remote Access policy completely

```text
unset remote-access policy
```

---

## AI one-shot partial edit of existing Rule

```text
set remote-access block-partner-ssh disabled
```

Only the enabled state changes.

---

## Test AI-generated Bundle from stdin

```text
test configuration -
```

Paste raw YAML and finish with:

```text
:end
```

---

## Diff AI-generated Bundle

```text
system diff configuration -
```

---

## Apply AI-generated Bundle

```text
system apply configuration -
```

Apply always re-validates the pasted Bundle and current authoritative state.

---

# 107. Final design statement

DRLink CLI v2.4 is built around one consistent operating model:

```text
Objects define reusable selectors and services.

Remote Services provide real connectivity.

Access Policies decide whether that connectivity or AI permission is allowed.

BLACKLIST defines blocks.
WHITELIST defines allows.

Human operators use Guided Wizards.

AI uses complete one-shot CLI for one Resource.

AI uses ConfigurationBundle for multiple dependent Resources.

Server and Agent configuration remain separate atomic contexts.
Agent Remote Service create/edit remains valid during temporary Server disconnect when local dependency validation succeeds; runtime endpoint allocation/activation may remain DEGRADED until reconnect.

All paths converge on the same validation, security-impact, transaction,
runtime activation, verification, audit, and final state.
```

This is the canonical CLI and AI-configuration behavior for Data Relay Link v2.4.
