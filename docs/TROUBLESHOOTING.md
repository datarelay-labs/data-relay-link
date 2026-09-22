# Data Relay Link — Troubleshooting

> **Status:** v2.4 operator guide
> **Authority:** This guide does not redefine product behavior. Use the Product Master and CLI/AI Master for normative semantics.

## 1. Start with identity and role

Run:

```text
show version
show status
```

Confirm:

```text
Data Relay Link version
release channel
Source HEAD
Relay Engine version
role = DRLink Server or Agent Host
```

A wrong-role command should tell you which host context owns the operation.

## 2. Run diagnostics

```text
system diagnostics
```

When escalation/evidence is needed:

```text
system support-bundle
```

Support bundles must redact raw secrets and sensitive payloads.

## 3. Remote Service is DEGRADED

On the owning Agent Host:

```text
show remote-service <NAME>
show remote-services
```

Common DEGRADED categories include:

```text
destination unreachable
Agent temporarily disconnected
Server temporarily unreachable
target service unavailable
new endpoint pending allocation
reconciliation dependency changed
```

A valid DEGRADED configuration is retained. Do not delete/recreate it merely because of a temporary outage unless the configuration itself is wrong.

After connectivity returns, synchronization/activation should recover without changing an existing endpoint reservation.

## 4. Endpoint says Pending allocation

This can occur when a new Remote Service is validly created while the Server cannot allocate an endpoint.

Expected lifecycle:

```text
configuration saved
→ DEGRADED
→ Endpoint: Pending allocation
→ reconnect/synchronize
→ allocate endpoint
→ HEALTHY
```

If allocation remains pending after Server recovery, inspect pool capacity and diagnostics.

## 5. Policy says ALLOW but connection fails

Authorization and connectivity are separate.

Remote Access:

```text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
```

Then inspect the owning Remote Service.

An ALLOW result does not prove destination reachability or runtime health.

## 6. Internet Access failure

Use:

```text
show internet-access
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
```

Check that:

- source selector is valid;
- destination is an allowed IP/CIDR/FQDN object;
- destination is not a Managed Host;
- selected Service Object uses a supported Internet Access transport;
- DNS/security validation did not reject the resolved address.

Unsafe, private/local/metadata, malformed, or ambiguous destinations fail closed according to `CONTROLLED_EGRESS.md` and `SECURITY.md`.

## 7. AI Access failure

Check separately:

```text
AI authentication
AI Access policy
destination selector
Permission Object / Permission Group
target OS permissions
```

Test:

```text
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
```

Authentication failure is not corrected by disabling policy enforcement.

## 8. ConfigurationBundle rejected

First run:

```text
test configuration <FILE|->
```

Canonical input begins with:

```yaml
configurationBundle:
  context: server
```

or:

```yaml
configurationBundle:
  context: agent
```

Common causes:

```text
wrong context
legacy/non-canonical schema
unknown section
missing required field
missing dependency
invalid selector
unsupported UDP Remote Service
state: absent combined with present-state fields
referenced resource deletion
```

No partial authoritative mutation should remain after validation failure.

## 9. Apply failed

If critical runtime activation fails, the product attempts to restore the previous authoritative/runtime state.

If output reports incomplete rollback, do not assume the prior state is fully active.

Run:

```text
system diagnostics
show status
```

and preserve the failure evidence before further mutation.

## 10. Referenced resource cannot be deleted

Use the relevant reference view:

```text
show network-object <OBJECT> references
show network-group <GROUP> references
show service-object <SERVICE> references
show service-group <GROUP> references
```

Remove or change dependent references first. Data Relay Link does not cascade-delete policy dependencies.

## 11. Policy mode change rejected

A configured BLACKLIST is not directly flipped to WHITELIST, and vice versa.

Use:

```text
1. export/record existing policy if needed
2. unset <access-policy> policy
3. create the first rule in the new mode
4. recreate required rules
```

This prevents silent reversal of existing rule meaning.

## 12. Version/provenance mismatch

Before stable release, candidate validation uses an exact immutable SHA or explicitly qualified candidate artifact.

If version/channel/source metadata disagree, treat the candidate as not qualified and consult `VERSION_POLICY.md` and `RELEASE_VALIDATION.md`.

## 13. External network prerequisites

Data Relay Link does not automatically fix external:

```text
cloud security groups
firewall/NAT/DNAT
DNS-provider records
SSH accounts
target application configuration
application certificates
```

Distinguish product failure from environment prerequisites before weakening product security.
