# Data Relay Link — Security Architecture

> **Document role:** Canonical security invariants and trust boundaries
> **Status:** v2.4.0 target architecture; implementation qualification pending
> **Technical SSOT:** `CONTROL_PLANE_ARCHITECTURE.md`

`Data Relay Link` **2.4.0**
Pinned FRP version: **0.71.0**

## 1. Security principle

Data Relay Link is default deny and fail closed.

It relays explicitly authorized connections/operations; it does not create broad network trust.

The product has three policy planes:

```text
Remote Access     outside → inside
Internet Access   inside → outside
AI Access         authenticated AI principal → internal endpoint capability
```

Each plane has separate semantics but shares durable identity, revisions, audit, and SQLite transaction infrastructure.

## 2. Authoritative state

The v2.4.0 target authoritative control-plane state is:

```text
/var/lib/drlink/drlink.db
```

Legacy `registry.json`, `access-control.json`, and `egress-control.json` are not authoritative target state.

Runtime artifacts are derived from a specific DB revision.

## 3. SQLite hardening

Required baseline:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA trusted_schema = OFF;
```

Database and secret files are root-owned with restrictive modes appropriate to their contents.

An unsupported newer schema, failed integrity check, or corruption that prevents safe interpretation fails closed.

## 4. Runtime generation integrity

Policy runtime state is compiled from the DB and activated atomically.

Every active plane records the source revision.

Example:

```text
DB Revision       : 42
Remote Policy     : 42 active
Internet Policy   : 42 active
AI Policy         : 42 active
```

A generation mismatch is surfaced and must not be treated as normal healthy enforcement.

## 5. Transaction boundary

Security-relevant mutations use a common sequence:

```text
validate
→ resolve references
→ calculate impact
→ confirm broadening where required
→ BEGIN IMMEDIATE
→ optimistic-concurrency recheck
→ write authoritative state
→ revision + audit
→ COMMIT
→ compile
→ validate
→ atomic activate/reload
→ verify active generation
```

Partial writes are not accepted as successful mutations.

## 6. Durable identity

Names are display identities. Durable references use immutable internal IDs.

This prevents rename operations from silently detaching policy.

Managed Endpoint identity is tied to the enrolled client/machine identity, not label, hostname, or observed public/NAT IP.

## 7. Reference protection

Policy dependencies are not cascade-deleted.

Deletion of a referenced Object, Object Group, AI Principal, Client Group, or other durable policy entity fails and lists references.

A removed Client's referenced Managed Endpoint may remain Orphaned rather than silently rebinding to a new client.

## 8. Optimistic concurrency

Interactive editing must detect stale state using `row_version` or equivalent.

Lost updates fail with no applied change.

SQLite writer serialization alone is not considered sufficient protection against stale wizard state.

## 9. Remote Access boundary

Remote Access authorization and Published Service reachability are both required.

```text
rule ALLOW
+
enabled Published Service
+
reachable connector/target
=
effective access
```

A network Object match alone does not expose arbitrary hosts or ports.

SELF Published Services use the Managed Endpoint as effective destination even if the local socket target is loopback.

ROUTED Published Services use the explicit routed target as effective destination.

## 10. Remote Access rule semantics

```text
ordered top-down
first complete match wins
ALLOW / DENY
implicit final DENY
```

No hidden specificity algorithm overrides rule order.

Policy changes apply immediately to new connections. Established connections are not implicitly terminated by a policy edit.

## 11. Internet Access boundary

Internet Access must never operate as an open proxy.

Required controls:

```text
explicit source authorization
explicit destination authorization
explicit protocol/port
default deny
server-side DNS where applicable
FQDN canonicalization
DNS rebinding resistance
validated exact-IP connection
private/local/link-local/metadata protection
safe IP-literal semantics
CONNECT/SNI binding where applicable
ECH-safe behavior
resource/time limits
safe logs
```

Ambiguous parsing or unsafe resolution fails closed.

## 12. Object context validation

Objects are neutral but context validation is mandatory.

An Object Group assignment fails as a whole if any member is invalid in the selected policy field.

Silently ignoring invalid members is prohibited.

Nested Object Group cycles are prohibited.

## 13. Policy-impact analysis

Security changes are not limited to Rule edits.

Impact analysis covers:

```text
Object value changes
Object Group membership
Rule content/order/enablement/action
Published Service target/mode
Managed Endpoint address membership changes
AI target/capability/path/exec constraints
```

At minimum calculate access broadened/narrowed, affected active rules, shadowing changes, and effective-action changes.

Interactive broadening defaults to No.

## 14. Secrets

The SQLite control plane does not require raw secret material to live in tables.

Root-owned secret storage may contain:

```text
CA private key
TLS private key
FRP/upstream raw transport token
bootstrap/enrollment verifier/hash and lifecycle metadata
MCP/OAuth client or signing secret where required
```

The DB may store references, hashes, IDs, status, and rotation metadata.

Secrets must not appear in:

```text
normal show output
help
Tab completion
audit records
public metadata
support bundles without deliberate protected handling
logs
ConfigurationBundle export/input generated for review
AI-generated configuration blocks
```

For v2.4 stable Zero-Touch, raw ticket/install URL material is returned only at issuance time. The server stores the verifier/hash required for validation, plus non-secret lifecycle metadata; it does not retain a redisplayable raw ticket.

ConfigurationBundle and AI-assisted configuration are never secret-distribution channels. Applying a bundle that attempts to embed a raw enrollment ticket, install credential, private key, OAuth/static bearer secret, or equivalent protected value fails validation before mutation.

## 15. PKI and management identity

Remote transport authentication and Data Relay Link management identity remain separate trust concepts.

Management paths use authenticated encrypted transport and persistent endpoint identity. Existing secure enrollment/CA fingerprint principles are retained unless superseded by a stronger explicit design.

Do not reuse an upstream FRP token as a general management or MCP credential.

## 16. MCP Bridge trust boundary

MCP is included in the v2.4.0 target.

Remote MCP calls terminate at a Data Relay Link server-side bridge. Internal endpoints do not expose independent MCP servers by default.

```text
MCP host
→ authenticated HTTPS https://<control-host>/mcp
→ loopback MCP Bridge 127.0.0.1:6103
→ AI Principal (Static Bearer or OAuth)
→ AI Access authorization
→ managed client control path
→ target OS boundary
```

The bridge does not bypass client identity, AI Access policy, or target OS permissions. Authorized operations are dispatched through a dedicated authenticated Data Relay Link client management/RPC path; Published Services and exposed SSH are not prerequisites for MCP operation.

## 17. MCP protocol baseline

Implementation must use the then-current official MCP specification and supported SDK behavior.

At the September 2026 architecture freeze, the modern remote direction is HTTP-native Streamable HTTP with the `2026-07-28` protocol revision available. Legacy SSE-first transport is not the new design target.

Exact authorization/transport mechanics are re-verified immediately before implementation and Real E2E.

## 18. AI Principal authentication

Every privileged MCP operation has an authenticated AI Principal.

Requirements:

```text
strong binding to credential/subject
revocation
rotation
no anonymous privileged tool call
server-side authorization every invocation
least privilege
rate/resource controls
audit attribution
```

Do not assume that a network source IP is sufficient AI identity.

## 19. AI capability authorization

Capabilities are explicit grants.

Initial required surface includes:

```text
exec
read_file
write_file
upload_file
download_file
```

Unknown or ungranted tools are denied.

Each tool invocation is authorized using the current ordered AI Access policy. Evaluation is top-down first complete match with explicit ALLOW/DENY and implicit final DENY.

## 20. Read-only AI semantics

`exec` is powerful enough to mutate files/system state through the shell.

Therefore:

```text
true read-only role => exec=false
```

If `exec=true`, the effective security boundary also includes:

```text
target OS user
filesystem permissions
sudo policy
shell/environment restrictions
timeout/process controls
optional sandbox/isolation if implemented
```

Do not market a role as read-only merely because direct `write_file` is denied. Execution identity and privilege elevation should be explicit constraints; granting `exec` alone never implies permission to elevate privileges.

## 21. AI path scopes

Direct file operations enforce configured path scopes after safe canonical path resolution.

Implementation must defend against traversal/symlink/path-normalization bypasses appropriate to the supported OS.

A path that cannot be proven inside the allowed scope is denied.

## 22. AI upload/download

Transfers enforce:

```text
principal authorization
target authorization
capability authorization
path scope
size/resource limits
safe temporary-file handling
atomic destination semantics where appropriate
audit metadata
```

Do not persist file contents in the audit database.

## 23. AI exec

`exec` enforcement includes:

```text
principal + target authorization
explicit exec capability
timeout
bounded output handling
process lifecycle management
safe environment construction
OS-account privilege boundary
audit attribution
```

Command allowlists/denylists may be added, but must not be represented as a complete sandbox when the OS account remains broadly privileged.

## 24. AI audit

Record bounded metadata:

```text
timestamp
principal
target endpoint
tool
matched rule
result
duration
revision
```

For exec, store a sanitized command summary/fingerprint and exit code as appropriate; avoid unrestricted sensitive output.

For file operations, store path, byte count/direction, result, and rule attribution; not file content.

## 25. Policy timing for AI

> **Policy changes apply immediately to new operations.**

A new MCP tool call sees current policy.

A command already running is not implicitly killed by a later policy edit unless the operator invokes an explicit cancellation mechanism.

## 26. Audit integrity

Configuration audit and AI activity are durable metadata in the control plane.

Audit writes must not be able to convert a denied operation into an allowed operation if audit persistence fails; fail behavior should preserve security and report loss of audit guarantees clearly.

## 27. Backup security

A live WAL DB is backed up with SQLite Online Backup or equivalent.

Backup archives may contain security-sensitive control state and trust material. They require restrictive ownership/permissions and validation before restore.

Restore performs schema, integrity, foreign-key, ownership/mode, and runtime-generation validation.

## 28. Database migration security

Upgrade sequence:

```text
consistent pre-upgrade backup
→ compatibility check
→ BEGIN IMMEDIATE
→ migrations
→ foreign_key_check
→ integrity validation
→ migration ledger update
→ COMMIT
→ policy compile
→ runtime activate
→ generation verify
```

Old binaries facing unsupported newer schema fail closed.

## 29. Support bundle

Support bundles must redact or omit:

```text
raw secrets
private keys
bootstrap tickets
MCP/OAuth tokens
sensitive command/file payloads
private customer data not required for diagnosis
```

They may include bounded schema/version/revision/generation metadata and safe health evidence.

## 30. Public endpoint separation

Preserve the product contract:

```text
public_ip / public_host
  control/allocator identity

public_hostname
  optional published-service alias

bootstrap_hostname
  bootstrap entrypoint
```

Do not silently mix these identities during installer/config generation.

## 31. External infrastructure boundary

Data Relay Link does not silently modify cloud security groups, external firewalls, NAT/DNAT, DNS, SSH accounts, or application TLS certificates.

Incorrect external infrastructure is classified as an environment/configuration issue rather than bypassed by weakening product security.

## 32. Fail-closed examples

The following must deny or stop affected enforcement safely:

```text
corrupt DB
unsupported DB schema
missing required durable reference
Object Group cycle
context-invalid group assignment
unsafe DNS answer
runtime generation cannot be verified
MCP auth failure
unknown AI Principal
unknown capability
path-scope violation
malformed tool request
```

No fallback to legacy JSON authority is permitted in the stable target.

## 33. Release security gates

v2.4.0 stable requires evidence for:

```text
SQLITE_INTEGRITY=PASS
DB_CORRUPTION_FAIL_CLOSED=PASS
REFERENCE_INTEGRITY=PASS
OPTIMISTIC_CONCURRENCY=PASS
POLICY_IMPACT_ANALYSIS=PASS
RUNTIME_GENERATION_CONSISTENCY=PASS
BACKUP_RESTORE=PASS
REMOTE_ACCESS_SECURITY_REGRESSION=PASS
INTERNET_ACCESS_SECURITY_REGRESSION=PASS
MCP_AUTH=PASS
MCP_CAPABILITY_ENFORCEMENT=PASS
MCP_FILE_SCOPE=PASS
MCP_AUDIT=PASS
MCP_REAL_E2E=PASS
CONFIGURATION_BUNDLE_SECRET_EXCLUSION=PASS
CONFIGURATION_REDACTED_EXPORT=PASS
CONFIGURATION_ATOMICITY=PASS
CONFIGURATION_REVISION_CONFLICT=PASS
ZERO_TOUCH_MAX_10_PER_REQUEST=PASS
ZERO_TOUCH_MAX_10_ACTIVE_UNUSED=PASS
ZERO_TOUCH_SINGLE_USE=PASS
ZERO_TOUCH_DOUBLE_USE_ATOMIC_DENY=PASS
ZERO_TOUCH_RAW_SECRET_NOT_STORED=PASS
SECRET_SCAN=PASS
PUBLIC_METADATA_SCAN=PASS
```

For the v2.4 stable target, enrollment tickets are unique single-use credentials whose raw value is displayed only at issuance. Server-side persistent state stores a verifier/hash plus lifecycle metadata rather than a redisplayable raw ticket. Post-success reuse is classified as `BOOTSTRAP_TICKET_USED`, and concurrent double-use must have exactly one successful consumer.
