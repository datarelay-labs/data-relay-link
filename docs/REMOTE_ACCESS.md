# Data Relay Link — Remote Services and Remote Access

> **Status:** v2.4 operator/developer guide
> **Authority:** Exact CLI behavior is defined by `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md`.

## 1. Two separate concepts

```text
Remote Service
→ creates/represents connectivity

Remote Access
→ decides whether a request to that connectivity is allowed
```

A policy Rule never creates a Remote Service.

## 2. Remote Service ownership

Remote Service mutation is local to the owning Agent Host.

Agent Host:

```text
show remote-services
show remote-service <NAME>
set remote-service <NAME>
unset remote-service <NAME>
```

Server inspection is read-only:

```text
show managed-host <HOST> remote-services
```

If destination is not the current Agent Host, the current Agent Host acts as the Relay Host.

## 3. Service selection

One Remote Service uses exactly one Service Object.

Supported:

```text
TCP
Fixed TCP
```

Rejected:

```text
UDP
Service Group
multi-target destination
```

## 4. Direct-host example

On the Agent Host:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

The endpoint is allocated/managed by Data Relay Link.

## 5. Relay Host example

On `branch-gateway`:

```text
set remote-service internal-db-postgres destination internal-db service postgres enabled
```

`branch-gateway` is the Relay Host. `internal-db` does not need to run a DRLink Agent merely to be the target of that relayed service.

## 6. Runtime states

```text
HEALTHY
DEGRADED
DISABLED
```

`DEGRADED` means configuration remains valid but runtime connectivity, synchronization, destination reachability, or endpoint allocation is temporarily unavailable.

`DISABLED` is deliberate operator state.

## 7. Endpoint stability

Endpoint reservation remains stable across:

```text
Agent restart
temporary disconnect
disable / enable
same endpoint-pool-class edit
```

Deletion returns the reservation after required synchronization.

A temporary failure must not unexpectedly reassign a different public endpoint.

## 8. Fixed TCP

Fixed TCP is a Service Object subtype.

The Service Object port is the destination TCP service port.

The public endpoint port is allocated separately from a dedicated Fixed TCP endpoint pool.

The user does not select the public endpoint port.

An existing Remote Service cannot change in-place between standard TCP and Fixed TCP pool classes. Delete and recreate when changing pool class.

## 9. Remote Access policy

Server policy commands:

```text
show remote-access
show remote-access <RULE>

set remote-access <RULE>
set remote-access enabled
set remote-access disabled

unset remote-access <RULE>
unset remote-access policy

test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
```

Initial state:

```text
No Policy
No Rules
Effective access = ALLOW
```

BLACKLIST:

```text
matching enabled Rule → DENY
no enabled Rule match → ALLOW
```

WHITELIST:

```text
matching enabled Rule → ALLOW
no enabled Rule match → DENY
```

Rules are not ordered and do not carry a per-rule ALLOW/DENY action.

## 10. Enforcement vs reset

```text
set remote-access disabled
```

preserves Mode and Rules but makes the effective policy ALLOW ALL.

```text
unset remote-access policy
```

removes Mode and all Remote Access Rules and returns the policy area to the initial no-policy ALLOW state.

These are different operations.

## 11. Effective connectivity

A successful connection requires all applicable runtime and authorization conditions:

```text
Remote Service enabled
+
Agent/runtime available
+
destination reachable
+
Remote Access permits the request
(or no policy exists)
```

A policy result of ALLOW does not imply that the target service is reachable.

## 12. Troubleshooting

Use:

```text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
show managed-host <HOST> remote-services
show remote-service <NAME>     # on owning Agent Host
system diagnostics
```

Policy-test output and Remote Service runtime status should be read separately: authorization can be ALLOW while connectivity is DEGRADED.
