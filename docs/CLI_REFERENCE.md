# Data Relay Link — CLI Reference

> **Status:** v2.4 active
> **Primary CLI:** `drlink`
> **Authoritative behavior:** `docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`

This document is a compact public command reference. The Master defines exact semantics when an example here is abbreviated.

## 1. Command model

Inside the REPL:

```text
drlink> show status
drlink> set network-object github
```

From a shell:

```bash
drlink show status
drlink set network-object github
```

Common roots:

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

Discovery:

```text
?
help
help managed-hosts
help network-objects
help commands
<verb> ?
Tab completion
```

## 2. Server show commands

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

## 3. Server set commands

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

Bare named `set` enters Guided Create/Edit. A complete one-shot form skips the Wizard.

Examples:

```text
set network-object github type fqdn value github.com
set network-object office-admin type ip value 203.0.113.10

set network-group approved-admins members office-admin,vpn-admin

set service-object ssh type tcp port 22
set service-object dns-udp type udp port 53
set service-object legacy-db type fixed-tcp port 1521

set service-group web-services members http,https

set permission-object read-only permissions host-info,process-read,file-read
set permission-group operators members read-only,operator

set ai-access allow-read mode whitelist source automation-ai destination ubuntu-prod permission read-only paths /var/lib/vendor/** enabled
```

## 4. Access Policy commands

First non-interactive Rule in an unconfigured policy must include `mode`.

Remote Access:

```text
set remote-access block-partner mode blacklist source partner-office destination ubuntu-prod service ssh enabled
```

Internet Access:

```text
set internet-access github-https mode whitelist source ubuntu-prod destination github service https enabled
```

AI Access:

```text
set ai-access claude-prod mode whitelist source claude destination production-servers permission read-only enabled
set ai-access allow-read mode whitelist source automation-ai destination ubuntu-prod permission read-only paths /var/lib/vendor/**,/opt/app/** enabled
```

File permissions (`file-read` / `file-write` / `file-upload` / `file-download`) use rule-bound `paths` scopes. Omit `paths` on edit to preserve existing scopes; use `paths -` or `paths none` to clear. Missing scopes remain fail-closed at runtime (no unrestricted filesystem default).

When Policy Mode already exists, `mode` may be omitted. A conflicting requested mode is rejected.

Policy enforcement:

```text
set remote-access enabled
set remote-access disabled
set internet-access enabled
set internet-access disabled
set ai-access enabled
set ai-access disabled
```

Rule disable excludes only that Rule from evaluation.

## 5. Policy semantics

Initial state:

```text
No Policy
No Rules
Effective = ALLOW
```

BLACKLIST:

```text
match    → DENY
no match → ALLOW
```

WHITELIST:

```text
match    → ALLOW
no match → DENY
```

There is no public rule-order command and no per-rule `allow|deny` action field.

## 6. Server unset commands

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

Referenced Objects/Groups/Identities/Managed Hosts are protected from deletion until references are removed.

## 7. Policy test commands

```text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION> [path <PATH>]
```

Output includes Mode, Enforcement, selectors, matched Rules, and Effective Result. Where relevant, Remote Service runtime state is shown separately from policy authorization.

When a selector is a Network Group, Service Group, or Permission Group, the public test expands every leaf member (stable sorted order), evaluates each concrete combination with the same atomic/runtime evaluators used for single Objects, and reports member/combination detail. Top-level Effective Result is ALLOW only when every expanded member/combination is ALLOW; mixed outcomes aggregate to DENY. Single Object / Service / Permission Object / atomic permission behavior is unchanged.

For file permissions, omit `path` and `test ai-access` will not claim unconditional ALLOW (runtime requires an in-scope path). Provide `path <PATH>` to evaluate the same fail-closed path-scope contract used by MCP. Permission Groups that include file permissions apply that fail-closed rule per file member before aggregation.

## 8. Server system commands

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

test configuration <FILE|->
system export configuration <FILE>
system diff configuration <FILE|->
system apply configuration <FILE|->

system certificate
system update
system support-bundle
system uninstall
```

## 9. Managed Host as Network Object

Registered Managed Hosts appear in `show network-objects` with type `Managed Host`.

Managed Host lifecycle is never performed through `set/unset network-object`.

Internet Access source may use a Managed Host. Internet Access destination may not use a Managed Host, directly or through a Network Group.

## 10. Agent Host commands

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

Agent one-shot example:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

Relay example executed on `branch-gateway`:

```text
set remote-service internal-db-postgres destination internal-db service postgres enabled
```

The current Agent Host is the Relay Host.

## 11. Remote Service contract

Remote Service uses exactly one Service Object.

Supported:

```text
TCP
Fixed TCP
```

Rejected:

```text
UDP
Service Group
CIDR/multi-target destination
duplicate Destination + Service on the same Agent
```

States:

```text
HEALTHY
DEGRADED
DISABLED
```

A valid but temporarily unreachable destination is saved as `DEGRADED`.

New valid Remote Service created while the Server is unavailable may show:

```text
Status   : DEGRADED
Endpoint : Pending allocation
```

After reconnect, DRLink synchronizes, allocates/activates, and transitions to `HEALTHY`.

## 12. Fixed TCP

Fixed TCP is a Service Object subtype.

```text
set service-object legacy-db type fixed-tcp port 1521
```

The external endpoint is allocated when an Agent creates a Remote Service using that Service Object. Standard TCP and Fixed TCP Remote Services use separate endpoint pools.

An existing Remote Service cannot change in place across standard TCP and Fixed TCP pool classes.

## 13. AI Identity

```text
set ai-identity <NAME>
show ai-identities
show ai-identity <NAME>
unset ai-identity <NAME>
```

Interactive AI binds through OAuth Authorization Code verification.

Automation / Custom AI binds through OAuth Client Credentials verification.

Authentication is distinct from AI Access authorization.

## 14. ConfigurationBundle

```text
test configuration <FILE|->
system diff configuration <FILE|->
system apply configuration <FILE|->
system export configuration <FILE>
```

stdin terminator:

```text
:end
```

Server Bundle and Agent Bundle are independently atomic within their current CLI context. Cross-context distributed atomicity is not provided.

## 15. Wrong-context errors

Server-only policy/Object mutation on an Agent Host must say the command belongs on the DRLink Server.

Agent-local Remote Service mutation on a Server must say it belongs on the owning Agent Host.

Do not reduce a known role error to an unexplained `Unknown command`.

## 16. Error contract

User-facing errors should state:

```text
what is wrong
what is required
whether a change was applied
what to do next
```

Raw traceback or backend database errors are not the public error contract.

## 17. Obsolete intermediate grammar

The following are not canonical v2.4 public resources/semantics:

```text
object / object-group as the only neutral public object hierarchy
managed-endpoint
published-service
service-preset
ai-principal
ordered-rule movement
per-rule ALLOW/DENY action
implicit default-DENY-only policy model
```

Use the Network/Service/Permission Object model, AI Identity, Remote Service, and BLACKLIST/WHITELIST semantics defined by the Master.
