# Data Relay Link v2.4.0 — ConfigurationBundle and AI-Assisted Configuration

> **Document role:** Canonical design contract for declarative configuration and AI-generated operator input before v2.4.0 stable
> **Authority:** `PRODUCT_MASTER.md` and `DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md` define public behavior; this document defines the configuration-ingestion surface that must reuse the same control-plane engine.

## 1. Release decision

ConfigurationBundle support is part of the v2.4.0 stable target. It is not deferred to v2.5.0.

The feature exists to support two operator workflows without creating a second configuration engine:

```text
simple request
  → AI or human emits one canonical public drlink command

multi-resource request
  → AI or human emits one ConfigurationBundle
  → validate / test / diff / confirm / atomic apply
```

Both paths MUST converge on the same control-plane mutation, policy-impact, revision, audit, compile, and activation logic.

## 2. Non-negotiable invariants

```text
CONFIGURATION_SSOT=server SQLite state
CONFIGURATION_FILE_IS_SSOT=NO
SEPARATE_YAML_POLICY_ENGINE=NO
SEPARATE_AI_POLICY_ENGINE=NO
DIRECT_DB_MUTATION_FROM_BUNDLE=NO
DIRECT_RUNTIME_JSON_MUTATION_FROM_BUNDLE=NO
ATOMIC_MULTI_RESOURCE_APPLY=YES
IDEMPOTENT_REAPPLY=YES
EXPLICIT_DELETE_ONLY=YES
REDACTED_EXPORT=YES
REVISION_CONFLICT_FAILS=YES
SECURITY_BROADENING_CONFIRMATION=YES
SECRETS_IN_EXPORT=NO
ZERO_TOUCH_SECRET_IN_BUNDLE=NO
```

A ConfigurationBundle is an idempotent change set against current server state. It does not take ownership of every resource on the server.

Objects omitted from a bundle remain unchanged. Deletion requires an explicit absent state.

## 3. Canonical CLI surface

The stable direct roots remain:

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

Do not reintroduce a top-level `apply` root.

Configuration operations live under existing roots:

```text
system export configuration drlink.yaml
test configuration drlink.yaml
system diff configuration drlink.yaml
system apply configuration drlink.yaml
```

Standard input is supported for AI copy/paste workflows:

```bash
sudo drlink system apply configuration - <<'DRLINK_CONFIG'
configurationBundle:
  context: server

  networkObjects:
    - name: hq-admin
      type: ip
      value: 203.0.113.10

  serviceObjects:
    - name: ssh
      type: tcp
      port: 22

  remoteAccess:
    mode: whitelist
    enforcement: enabled
    rules:
      - name: hq-admin-ssh
        source: hq-admin
        destination: ubuntu-prod
        service: ssh
        enabled: true
DRLINK_CONFIG
```

`system apply configuration` MUST internally perform validation, embedded policy tests, diff, security-impact analysis, and confirmation before commit. Default confirmation is No.

## 4. AI output contract

An AI assistant should choose the smallest safe form.

Use one canonical CLI command when the requested change is simple and independently atomic, for example:

```text
one Object value change
one Group membership change
one rule enable/disable
one Zero-Touch ticket request
```

Use a ConfigurationBundle when several resources depend on each other or must succeed/fail together, for example:

```text
Objects + Groups + policies
multiple policy rules
initial branch deployment intent
large policy revision
review/change/reapply of exported configuration
```

AI-generated output MUST NOT use internal helpers, direct SQLite, authoritative/runtime JSON edits, hidden compatibility commands, secrets, private keys, or pre-generated enrollment URLs.

## 5. Change Plan engine

All mutating inputs converge on one Change Plan abstraction:

```text
direct public CLI ─┐
AI-generated CLI  ─┼→ Change Plan → validate → resolve references
ConfigurationBundle┘               → policy tests
                                    → diff
                                    → impact analysis
                                    → confirmation
                                    → optimistic-concurrency check
                                    → one authoritative transaction
                                    → revision + audit
                                    → compile / activate / verify
```

A bundle implementation that writes tables or runtime files through a separate code path violates this architecture.

The Change Plan contains at least:

```text
base revision
dependency-aware mutations
dependent references
before/after representation
policy-impact result
embedded test result
confirmation requirement
expected post-commit revision
```

## 6. Bundle semantics

Initial schema identifier:

```text
apiVersion: drlink.datarelay.run/v1alpha1
kind: ConfigurationBundle
```

Supported server-owned resource families SHOULD include the canonical v2.4 model rather than legacy nouns:

```text
objects
objectGroups
clientGroups
servicePresets
publishedServices where server-side mutation is actually supported
remoteAccess
internetAccess
fixedTcp
aiAccess references that do not contain credentials
enrollmentPlans
```

The schema MUST NOT expose `acl`, `serviceProfiles`, or `internetProfiles` as current resource families.

Resource identity and references use canonical immutable IDs internally and stable human-readable selectors at the input boundary.

## 7. Idempotency and ownership

Applying the same bundle twice against unchanged effective state MUST produce:

```text
NO CHANGE
```

A bundle is patch-like, not authoritative desired-state ownership of the whole server.

Therefore:

```text
missing from bundle  → preserve existing resource
state: present       → create/update idempotently
state: absent        → explicit delete request
```

Delete remains subject to reference protection and destructive confirmation.

## 8. Export

`system export configuration` produces a redacted, reviewable representation of server-owned configuration suitable for AI review and later re-application.

Export excludes:

```text
raw enrollment/Zero-Touch tickets
installation URLs containing credentials
OAuth/static bearer secrets
private keys
client identity private material
stored secret values
unbounded audit payloads
```

References to protected secrets may be exported only as non-secret identifiers/metadata where required.

Export SHOULD include the source revision so later diff/apply can detect intervening mutation.

## 9. Validation and embedded tests

`test configuration` is non-mutating.

Validation includes at least:

```text
YAML/schema validation
apiVersion/kind validation
canonical resource names
object type/context validation
reference resolution
cycle detection
policy Mode / Enforcement / Rule validity
duplicate/overlap diagnostics
Internet Access destination security validation
AI capability/path-scope validation
Fixed TCP destination validation
explicit delete/reference protection preflight
Zero-Touch plan constraints
```

A bundle may contain non-mutating expected-policy tests. All required tests must pass before apply can proceed.

A failed test rejects the complete change set.

## 10. Diff and confirmation

Before mutation, show a bounded human-readable Change Plan such as:

```text
Configuration validation: PASS
Policy tests:             2/2 PASS
Base revision:            42
Current revision:         42

Planned changes:
  + 2 Objects
  ~ 1 Remote Access rule
  - 0 Resources

Security impact:
  Public access added: NO
  Resources deleted:   NO
  Access widened:      NO

Apply these changes? [y/N]
```

Any security widening, public exposure, destructive deletion, credential lifecycle change, or other existing impact-confirmation condition remains governed by the same safety engine used by direct CLI.

## 11. Concurrency

A plan is built against a specific current revision.

If authoritative state changes between planning and commit:

```text
REVISION_CONFLICT
No changes were applied.
Re-run diff/test against current state.
```

Do not silently rebase a security-relevant bundle onto newer state.

## 12. Existing client boundary

The configuration surface MUST NOT claim that the server can remotely rewrite an existing client's local service target when that capability does not exist.

For existing clients:

```text
server-owned policy/group/reservation change
  → may be applied by server Change Plan

client-local target/service mutation not remotely supported
  → CLIENT_ACTION_REQUIRED
  → no false success
```

New Zero-Touch enrollment may carry explicitly authorized initial-service intent through the existing enrollment path where that path supports it.

## 13. Zero-Touch enrollment plans

ConfigurationBundle may declare deployment intent for future clients, but applying the bundle MUST NOT pre-issue installation secrets.

Example intent:

```yaml
spec:
  enrollmentPlans:
    - name: branch-01
      platform: linux
      clientGroups: [branch]
      initialServices:
        - preset: ssh-admin
          name: ssh
```

Result example:

```text
30 clients planned
0 Zero-Touch tickets issued
Next issuable batch: 10
```

A plan is not a Managed Host or DRLink Agent. Managed Host/Agent identity is created only by successful enrollment.

## 14. Zero-Touch issuance limits

Stable v2.4 server enforcement:

```text
MAX_TICKETS_PER_ISSUE_REQUEST=10
MAX_ACTIVE_UNUSED_TICKETS=10
TICKET_USE_COUNT=1
DEFAULT_TTL=1h
MAX_TTL=24h
```

If 3 valid unused tickets remain, at most 7 additional tickets may be issued.

Every ticket is unique and bound to one intended enrollment context. Do not issue one reusable credential with a use-count of 10.

The server stores only the verifier/hash needed to validate a ticket. Raw ticket/install URL is shown only at issuance time.

Successful enrollment atomically consumes the ticket so concurrent double-use cannot succeed.

Expired/revoked tickets no longer count toward the active-unused limit. Expiry/revocation of the enrollment ticket does not disconnect an already enrolled client.

Reinstall never reuses an already consumed ticket; use the supported recovery/re-enrollment path.

Neither YAML fields, hidden flags, nor API parameters may increase these server-side limits.

## 15. Zero-Touch batch lifecycle

After a ConfigurationBundle creates enrollment plans, ticket issuance is a separate explicit operator action immediately before installation.

The operator may request the next batch, up to the remaining active-unused capacity.

Required operator capabilities:

```text
show planned enrollments
issue next Zero-Touch batch
show ticket metadata without redisplaying secrets
revoke one ticket
revoke remaining tickets in a batch
show consumed/expired/revoked status
```

The exact public CLI grammar must remain action-first/canonical and must be discoverable through normal help/menu before stable qualification.

## 16. Audit

Every configuration operation records at least:

```text
actor
input path: direct-cli | configuration-file | configuration-stdin
bundle name where present
bundle content hash
base revision
committed revision
change summary
policy-impact summary
test summary
result
```

Do not write raw secrets or complete sensitive bundle content into audit storage.

## 17. Failure and rollback semantics

Validation, reference, test, security, or concurrency failure occurs before authoritative mutation.

If the authoritative transaction fails, no partial resource subset may remain committed.

If DB commit succeeds but runtime compile/activation fails, existing control-plane rules apply: DB remains authoritative, generation mismatch is surfaced, and affected enforcement fails closed where safe enforcement cannot be proven.

## 18. Explicit non-goals

ConfigurationBundle v1alpha1 is not:

```text
Terraform state
Ansible replacement
a second authoritative config database
continuous file reconciliation
a secret distribution mechanism
remote desktop/fleet-management system
a mechanism to overwrite all server state because a resource is omitted
```

## 19. Stable-release gates

v2.4.0 stable requires retained exact-HEAD evidence for:

```text
CONFIGURATION_BUNDLE_SCHEMA=PASS
CONFIGURATION_FILE_AND_STDIN=PASS
CONFIGURATION_VALIDATE=PASS
CONFIGURATION_DIFF=PASS
CONFIGURATION_IDEMPOTENCY=PASS
CONFIGURATION_EXPLICIT_DELETE=PASS
CONFIGURATION_ATOMICITY=PASS
CONFIGURATION_REVISION_CONFLICT=PASS
CONFIGURATION_POLICY_TESTS=PASS
CONFIGURATION_IMPACT_CONFIRMATION=PASS
CONFIGURATION_REDACTED_EXPORT=PASS
CONFIGURATION_SECRET_EXCLUSION=PASS
DIRECT_CLI_AND_BUNDLE_SEMANTIC_PARITY=PASS
AI_COPY_PASTE_REAL_E2E=PASS
EXISTING_CLIENT_BOUNDARY=PASS
ZERO_TOUCH_BATCH_MAX_10=PASS
ZERO_TOUCH_ACTIVE_UNUSED_MAX_10=PASS
ZERO_TOUCH_SINGLE_USE=PASS
ZERO_TOUCH_DEFAULT_TTL_1H=PASS
ZERO_TOUCH_MAX_TTL_24H=PASS
ZERO_TOUCH_SECRET_ONE_TIME_DISPLAY=PASS
ZERO_TOUCH_DOUBLE_USE_ATOMIC_DENY=PASS
```

The release is not qualified if the bundle path can create policy/state that the canonical direct CLI/change engine would reject.
