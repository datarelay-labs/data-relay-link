# Data Relay Link v2.4.0 — ConfigurationBundle and AI-Assisted Configuration

> **Document role:** Canonical operator/developer reference for ConfigurationBundle ingestion
> **Status:** v2.4 active
> **Authority:** `PRODUCT_MASTER.md` and `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md` define public behavior. This document must not redefine those semantics.
> **Implementation:** `lib/drlink_v24_bundle.py`

## 1. Purpose

ConfigurationBundle is the multi-resource configuration input for Data Relay Link.

Use it when several dependent resources must be validated and applied together.

```text
one independent resource
→ canonical public drlink command

multiple dependent resources
→ ConfigurationBundle
→ test / diff / apply
```

ConfigurationBundle is not a second configuration database or policy engine. It converges on the same Data Relay Link control-plane semantics as Human Guided Wizards and complete AI one-shot CLI.

## 2. Canonical document shape

The canonical v2.4 schema starts with:

```yaml
configurationBundle:
  context: server
```

or:

```yaml
configurationBundle:
  context: agent
```

The legacy development form:

```yaml
apiVersion: ...
kind: ConfigurationBundle
```

is not the canonical v2.4 input contract and must not be documented as the normal format.

## 3. Canonical CLI surface

From the `drlink>` prompt:

```text
test configuration <FILE|->
system diff configuration <FILE|->
system apply configuration <FILE|->
system export configuration <FILE>
```

From a shell, prefix the same command with `drlink` or `sudo drlink` as appropriate.

There is no top-level public `apply` command.

Each of `test`, `diff`, and `apply` independently parses and validates the supplied document. A previous successful test or diff is never an authorization token for a later apply.

## 4. Server ConfigurationBundle

A Server bundle may contain any subset of these canonical sections:

```text
networkObjects
networkGroups
serviceObjects
serviceGroups
permissionObjects
permissionGroups
remoteAccess
internetAccess
aiAccess
```

Example:

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: office-admin
      type: ip
      value: 203.0.113.10

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
        source: office-admin
        destination: github
        service: https
        enabled: true
```

Managed Hosts and verified AI Identities may be referenced by public name where the selected policy field permits them. They are not created merely by declaring a name in a Server ConfigurationBundle.

Enrollment and AI authentication remain lifecycle workflows.

## 5. Agent ConfigurationBundle

An Agent bundle manages Remote Services owned by the current Agent Host.

Canonical section:

```text
remoteServices
```

Example:

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
```

The current Agent Host is the implicit owner. When destination is not `this-host`, the current Agent Host acts as the Relay Host.

A Server bundle cannot contain `remoteServices`.

An Agent bundle cannot contain Server-owned Object, Group, Permission, or Access Policy sections.

Context mismatch is rejected before authoritative mutation.

## 6. Resource semantics

General rules:

```text
resource omitted
→ UNCHANGED

field omitted on an existing resource
→ UNCHANGED

state omitted
→ present/create-or-update semantics

state: absent
→ explicit deletion/reset request

same desired state
→ NO CHANGE
```

A ConfigurationBundle is a patch/desired-change document. It does not take ownership of every Data Relay Link resource.

A resource with `state: absent` cannot also describe desired present-state fields.

Invalid example:

```yaml
configurationBundle:
  context: server

  networkObjects:
    - name: old-network
      state: absent
      type: cidr
      value: 10.0.0.0/8
```

This fails validation and applies no change.

## 7. Exact-list fields

When these list fields are supplied, they represent the exact desired list for that resource:

```text
Network Group.members
Service Group.members
Permission Group.members
Permission Object.permissions
AI Access Rule.paths
```

Example:

```yaml
configurationBundle:
  context: server

  networkGroups:
    - name: approved-admins
      members:
        - office-admin
        - vpn-admin

  aiAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: allow-read
        source: automation-ai
        destination: ubuntu-prod
        permission: read-only
        paths:
          - /var/lib/vendor/**
        enabled: true
```

If `paths` is omitted on an existing AI Access rule, existing path scopes are preserved. An explicit empty `paths: []` clears scopes. Missing scopes remain fail-closed for file capabilities.

If `members` is omitted on an existing group, its membership remains unchanged.

## 8. Access Policy semantics

ConfigurationBundle uses the same Remote Access, Internet Access, and AI Access model as the canonical CLI.

```text
Mode:
  BLACKLIST
  WHITELIST

Enforcement:
  ENABLED
  DISABLED
```

There is no rule ordering and no per-rule ALLOW/DENY action.

For an unconfigured policy, creation of the first rule requires `mode`.

For an already configured policy:

```text
mode omitted
→ existing mode retained

enforcement omitted
→ existing enforcement retained

rules omitted
→ existing rules retained

rule omitted from rules[]
→ existing rule retained

rule with state: absent
→ that rule is deleted
```

A conflicting mode is rejected.

Whole-policy reset is explicit:

```yaml
configurationBundle:
  context: server

  remoteAccess:
    state: absent
```

Equivalent reset semantics apply to `internetAccess` and `aiAccess`.

## 9. Reference and context validation

The whole document is parsed before mutation.

```text
parse complete document
→ validate schema and fields
→ resolve references
→ validate context-specific selectors
→ build Change Plan
→ calculate diff and security impact
```

Declaration order does not control dependency resolution.

A rule may reference an Object created elsewhere in the same bundle.

A missing reference, duplicate public selector, invalid group member, unsupported transport, or wrong CLI context rejects the complete change set.

## 10. Internet Access selector rules

Internet Access source may use:

```text
IP
CIDR
FQDN
Managed Host
Network Group containing valid source members
```

Internet Access destination may use:

```text
IP
CIDR
FQDN
Network Group containing only valid destination Network Objects
```

Managed Host is not a valid Internet Access destination, directly or through a destination Network Group.

Internet Access v2.4 is TCP/HTTP/HTTPS-oriented. Unsupported UDP selections fail validation.

## 11. Remote Service rules

Agent `remoteServices` use exactly one Service Object.

Supported:

```text
TCP
Fixed TCP
```

Rejected:

```text
UDP
Service Group
CIDR or multi-target Network Group destination
```

Fixed TCP defines the destination TCP port in the Service Object. The public endpoint port is allocated separately from the Fixed TCP endpoint pool.

An existing Remote Service cannot be edited in-place between normal TCP and Fixed TCP endpoint-pool classes.

## 12. Agent operation while the Server is unavailable

Temporary Agent-to-Server disconnection does not automatically invalidate a locally valid Remote Service change when required synchronized metadata is available.

Existing Remote Service:

```text
edit locally
→ preserve existing endpoint reservation
→ DEGRADED while synchronization/runtime activation is unavailable
→ reconnect
→ synchronize
→ HEALTHY when runtime conditions recover
```

New Remote Service:

```text
valid local configuration
→ save
→ DEGRADED
→ Endpoint: Pending allocation
→ reconnect
→ allocate endpoint
→ activate
```

If a required dependency cannot be resolved from synchronized metadata, validation fails and no change is saved.

## 13. Test

`test configuration` is read-only.

It validates at least:

```text
YAML structure
configurationBundle.context
known section names
required fields
public-name validity
resource field validity
reference resolution
group membership
policy semantics
Server/Agent context
Remote Service transport/destination constraints
Internet Access selector constraints
explicit deletion/reference protection
```

Success does not mutate authoritative state.

## 14. Diff

`system diff configuration` is read-only.

It reports the current-state comparison using operations such as:

```text
CREATE
UPDATE
DELETE
NO CHANGE
```

It also reports security impact where applicable.

The diff is advisory evidence for that invocation only. Apply re-reads the current authoritative state.

## 15. Apply

`system apply configuration` performs the complete safety pipeline again:

```text
parse
→ validate
→ resolve
→ calculate Change Plan
→ recalculate current-state diff
→ calculate security impact
→ confirmation when required
→ authoritative transaction
→ runtime generation
→ activation
→ verification
```

Critical runtime activation or verification failure restores the previous authoritative/runtime state when rollback succeeds.

If rollback itself is incomplete, Data Relay Link must state that operator attention is required; it must not falsely say that no change occurred.

A valid-but-unreachable Remote Service is an operational `DEGRADED` state, not a configuration-transaction failure.

## 16. Concurrency

Apply evaluates the authoritative state that exists at execution time.

If state changed after an earlier test or diff, apply recalculates references, diff, and security impact.

The implementation must not blindly commit a stale previously displayed plan.

## 17. Idempotency

Applying the same desired state again produces:

```text
NO CHANGE
Configuration already matches the requested state.
```

A no-change reapply must not recreate resources, reallocate Remote Service/Fixed TCP endpoints, or restart runtime components unnecessarily.

## 18. Standard-input copy/paste

Use `-` for stdin:

```text
test configuration -
system diff configuration -
system apply configuration -
```

Interactive paste mode announces:

```text
Paste ConfigurationBundle YAML below.
Finish with a line containing only:
:end
```

`:end` is the CLI terminator and is not part of YAML.

AI output intended for direct paste should contain raw YAML only.

Markdown fences or explanatory prose inside the pasted input must fail safely rather than causing partial application.

## 19. Export and secrets

`system export configuration <FILE>` emits the canonical schema for the current CLI context:

```text
Server CLI
→ context: server

Agent CLI
→ context: agent
```

Export contains desired configuration, not transient health/reachability state.

Export must not disclose:

```text
OAuth tokens
Bearer tokens
Enrollment/Zero-Touch raw tickets
private keys
credentials
other protected secret material
```

Omitted secret material leaves existing secrets unchanged when a configuration is re-applied.

A display placeholder such as `REDACTED` is never interpreted as a new secret.

## 20. Zero-Touch boundary

Zero-Touch enrollment is a lifecycle workflow, not a canonical ConfigurationBundle section in v2.4.

Use the Server CLI enrollment workflow:

```text
set enrollment zero-touch
set enrollment manual
set enrollment bulk
```

Enrollment ticket rules remain server-enforced:

```text
maximum per issuance request     10
maximum active unused tickets   10
default TTL                     1 hour
maximum TTL                     24 hours
use count                       1
raw ticket                      displayed only at issuance
persistent credential           verifier/hash only
```

ConfigurationBundle must not be used as a channel for raw enrollment secrets.

## 21. AI-assisted configuration contract

AI is a configuration assistant, not a separate control plane.

For one resource, prefer a complete canonical one-shot command.

Example:

```text
set internet-access github-https mode whitelist source ubuntu-prod destination github service https enabled
```

For several dependent resources, use a ConfigurationBundle.

AI must use public names and canonical resource nouns. It must not generate direct SQLite edits, internal helper commands, runtime JSON mutations, hidden IDs, or secret-bearing configuration.

## 22. Acceptance contract

ConfigurationBundle is conformant only when all of the following hold:

```text
CANONICAL_TOP_LEVEL=configurationBundle
CONTEXT_REQUIRED=server|agent
SERVER_AGENT_CONTEXT_SEPARATION=PASS
SERVER_SECTIONS_MATCH_CANONICAL_V2_4_MODEL=PASS
AGENT_REMOTE_SERVICES_ONLY=PASS
EXPLICIT_DELETE_ONLY=PASS
OMITTED_RESOURCE_UNCHANGED=PASS
OMITTED_EXISTING_FIELD_UNCHANGED=PASS
EXACT_LIST_FIELD_SEMANTICS=PASS
REFERENCE_RESOLUTION_WHOLE_DOCUMENT=PASS
INVALID_FINAL_RESOURCE_CAUSES_ZERO_PARTIAL_MUTATION=PASS
TEST_NON_MUTATING=PASS
DIFF_NON_MUTATING=PASS
APPLY_REVALIDATES_CURRENT_STATE=PASS
SECURITY_IMPACT_RECALCULATED=PASS
IDEMPOTENT_REAPPLY_NO_CHANGE=PASS
EXPORT_REDACTS_SECRETS=PASS
STDIN_END_MARKER=:end
RUNTIME_FAILURE_ROLLBACK=PASS
TRUTHFUL_INCOMPLETE_ROLLBACK_ERROR=PASS
```

## 23. Non-goals

ConfigurationBundle does not introduce:

```text
a second SSOT
a second policy engine
cross-Server-and-Agent distributed atomic transactions
remote mutation of an Agent-local Remote Service from the Server CLI
automatic enrollment/authentication identity creation
raw secret distribution
direct database editing
direct runtime JSON editing
```

## 24. Authority rule

When this document conflicts with the current CLI/AI Master or actual canonical v2.4 parser contract, the conflict must be fixed here. Do not revive legacy development schemas or intermediate public nouns as an alternate supported ConfigurationBundle format.
