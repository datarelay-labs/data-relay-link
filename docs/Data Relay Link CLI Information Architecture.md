# Data Relay Link — Canonical CLI Information Architecture

> **Document role:** Derived CLI UX / navigation specification
> **Status:** v2.4 active
> **Primary CLI:** `drlink`
> **Authoritative CLI/AI SSOT:** `docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`

## 1. Authority

This document is derived from the v2.4 CLI/AI Master. If this document, older screenshots, tests, examples, or implementation disagree with the Master, the Master wins.

The previous intermediate model based on `Clients / Objects / Published Services / Service Presets / ordered ALLOW-DENY rulebases / AI Principals` is superseded and is not the v2.4 public CLI contract.

## 2. Core mental model

The v2.4 public model is:

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

Connectivity and authorization are separate:

```text
Managed Host + Service Object
→ Remote Service
→ actual connectivity / endpoint

Access Policy
→ authorization only
```

A Rule never creates a Remote Service.

## 3. CLI contexts

### DRLink Server

The Server manages:

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
Server ConfigurationBundle
system/revision/audit/backup/restore operations
```

### Agent Host

The Agent Host manages:

```text
Agent lifecycle
Remote Services owned by this Agent
Agent ConfigurationBundle
local diagnostics
```

Remote Service mutation is local to the owning Agent Host. The Server may inspect Remote Service state but does not mutate it.

## 4. Common verbs

```text
show   read-only
set    create / edit / enable / disable
unset  remove / delete / policy reset
test   validate / simulate / explain; never mutate
system system and configuration operations
```

## 5. Canonical Server menu

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

The root must identify the role as `DRLink Server`.

## 6. Canonical Agent Host menu

```text
Data Relay Link — Agent Host
├── 1. Status
├── 2. Remote Services
│   ├── List
│   ├── Create
│   └── Manage
│
├── 3. Agent
│   ├── Pause
│   ├── Resume
│   ├── Restart
│   ├── Autostart
│   └── Update
│
├── 4. Configuration
│   ├── Test
│   ├── Diff
│   ├── Apply
│   └── Export
│
├── 5. Diagnostics
├── 6. Help
└── 7. Exit
```

The root and `show status` must identify the role as `Agent Host`.
Diagnostics, support-bundle human output, menus, help, and errors use the same
`Agent Host` label. `show agent` is a required read-only Agent Host command.

## 7. Canonical terminology

| Term | Meaning |
|---|---|
| Managed Host | Real host managed by DRLink; also selectable as a Network Object where valid |
| DRLink Agent | Software installed on a Managed Host |
| Network Object | IP, CIDR, FQDN, or Managed Host selector |
| Network Group | Flat reusable collection of Network Objects |
| Service Object | TCP, UDP, or Fixed TCP service definition (public Wizard: SSH/HTTP/HTTPS/RDP/Custom TCP/Fixed TCP; UDP not offered in normal Wizard) |
| Service Group | Flat reusable collection of Service Objects |
| Permission Object | Reusable AI permission set |
| Permission Group | Reusable collection of Permission Objects |
| AI Identity | Verified authenticated AI identity |
| Remote Service | Agent-owned connectivity object with a DRLink endpoint |
| Relay Host | Current Agent Host when forwarding to another destination |
| Remote Access | Authorization policy for Remote Services |
| Internet Access | Authorization policy for outbound access |
| AI Access | Authorization policy for verified AI Identities |

The following intermediate public nouns are not canonical v2.4 CLI nouns:

```text
Managed Endpoint
Published Service
Service Preset
AI Principal
ordered first-match rule
explicit per-rule ALLOW/DENY action
```

## 8. Human Guided Create/Edit

For named resources:

```text
set <RESOURCE> <NAME>
```

means:

```text
name absent  → Create Wizard
name exists  → Edit Wizard
```

Wizard rules:

- invalid input stays on the current step;
- previous valid draft input is preserved;
- inline-created Objects remain draft until final Apply;
- Review shows the complete desired state;
- Edit Review shows Before / After;
- Cancel produces `No changes were applied.`;
- no inline draft may survive parent-Wizard cancellation.

Human Wizard, AI one-shot CLI, and ConfigurationBundle converge on the same Change Plan semantics.

## 9. Access Policy UX

Each policy family has:

```text
Mode:
  BLACKLIST
  WHITELIST

Enforcement:
  ENABLED
  DISABLED
```

Initial state:

```text
No Policy
No Rules
Effective access = ALLOW
```

BLACKLIST:

```text
enabled Rule matches → DENY
no enabled Rule match → ALLOW
```

WHITELIST:

```text
enabled Rule matches → ALLOW
no enabled Rule match → DENY
```

There is no rule ordering and no per-rule ALLOW/DENY action.

Deleting the last Rule preserves Policy Mode. Policy Reset is separate:

```text
unset remote-access policy
unset internet-access policy
unset ai-access policy
```

Policy Reset returns the area to `No Policy / No Rules / ALLOW`.

## 10. Remote Service UX

Remote Service is Agent-local.

```text
show remote-services
show remote-service <NAME>
set remote-service <NAME>
unset remote-service <NAME>
```

One Remote Service uses one Service Object.

Supported:

```text
TCP
Fixed TCP
```

Rejected for Remote Service:

```text
UDP
Service Group
multi-target destination
```

User-facing states:

```text
HEALTHY
DEGRADED
DISABLED
```

A valid but unreachable destination remains configured and becomes `DEGRADED`.

## 11. Fixed TCP UX

Fixed TCP is a Service Object subtype, not a separate policy/resource hierarchy.

```text
set service-object legacy-db type fixed-tcp port 1521
```

When a Remote Service uses it, DRLink allocates an endpoint from the separate Fixed TCP endpoint pool. The operator does not choose the external listen port.

## 12. AI Identity UX

```text
set ai-identity <NAME>
```

Interactive AI uses OAuth Authorization Code verification.

Automation / Custom AI uses OAuth Client Credentials verification.

A display name alone is never trusted identity. AI Access authorization is separate from authentication.

## 13. AI one-shot UX

One resource is one complete command.

Example:

```text
set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled
```

Missing dependencies are not silently created. Use ConfigurationBundle for dependent multi-resource changes.

## 14. ConfigurationBundle UX

Server and Agent contexts are independently atomic.

```text
test configuration <FILE|->
system diff configuration <FILE|->
system apply configuration <FILE|->
system export configuration <FILE>
```

stdin input ends with a line containing only:

```text
:end
```

A single distributed all-or-nothing Bundle spanning Server plus Agents does not exist.

## 15. Help and discovery

`?`, `help`, menus, completion, errors, and documentation must use the canonical nouns above and be role-aware.

Wrong-context operations must explain the correct execution context rather than returning only `Unknown command`.

## 16. Canonical invariants

```text
CLI_DIRECT_GRAMMAR=ACTION_FIRST
SERVER_ROLE_SEPARATION=YES
AGENT_REMOTE_SERVICE_OWNERSHIP=YES
MANAGED_HOST_NETWORK_SELECTOR=YES
FIXED_TCP_SERVICE_SUBTYPE=YES
REMOTE_SERVICE_UDP=NO
POLICY_MODES=BLACKLIST|WHITELIST
RULE_ORDERING=NO
RULE_ACTION_FIELD=NO
INITIAL_NO_POLICY_EFFECTIVE=ALLOW
WIZARD_ATOMICITY=YES
AI_ONE_SHOT_COMPLETE_RESOURCE=YES
BUNDLE_ATOMICITY=CURRENT_CLI_CONTEXT
```

## 17. Testing contract

Regression tests must protect:

- role-aware Server/Agent roots;
- canonical nouns and help/menu discovery;
- Guided Create/Edit and Cancel atomicity;
- BLACKLIST/WHITELIST semantics;
- policy disable/enable/reset;
- Managed Host Internet source and destination validation;
- Agent-local Remote Service ownership;
- Relay Host and DEGRADED behavior;
- Fixed TCP separate endpoint pool;
- UDP Remote Service rejection;
- AI Identity verification/binding;
- Server and Agent ConfigurationBundle parity;
- runtime activation rollback and truthful rollback-failure errors;
- wrong-context guidance;
- absence of legacy public nouns and ordered-rule semantics.
