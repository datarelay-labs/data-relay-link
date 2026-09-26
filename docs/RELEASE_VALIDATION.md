# Data Relay Link — v2.4.0 Release Validation

> **Purpose:** Validation plan for the final Control Plane / Object / Policy / MCP architecture
> **Rule:** Final stable evidence must come from the same exact source HEAD.

Current project version **2.4.0** / FRP **0.71.0**

Published tags are immutable.

### User E2E execution matrix

The canonical role-based real-user execution matrix is:

- USER_E2E_SCENARIOS.md

An unqualified request for "User E2E", "사용자 E2E", "Full User E2E", or "전체 E2E" means the FULL_USER_E2E profile in that document: all mandatory User, Operator, Administrator, security/failure, and performance scenarios using the actual public drlink CLI and real traffic. ChatGPT is the executor and final auditor for that profile.

Appendix A of the same file retains the v2.4 operator manual runbook. It does not replace FULL_USER_E2E and it is not a second canonical document.

A targeted subset is valid only when the requested scope is explicitly narrowed. Final release qualification still requires the exact-HEAD double Full Real E2E passes defined later in this document.

## 1. Gate philosophy

Validation must prove both allowed behavior and denied behavior.

Synthetic/unit tests are necessary but cannot replace Real E2E for final release qualification.

Failure classifications:

```text
PRODUCT_BUG
PLATFORM_COMPATIBILITY_BUG
TEST_HARNESS_BUG
ENVIRONMENT_BLOCKER
DOCUMENTATION_MISMATCH
RELEASE_METADATA_BUG
```

## 2. Automated validation order

Run in this order:

```text
static/syntax validation
schema/migration tests
Object/relationship tests
policy evaluator/compiler tests
impact/shadow tests
CLI targeted regressions
Internet Access security regressions
MCP auth/capability/path tests
backup/restore tests
version/release governance tests
full local automated suite
build/dist/source parity
```

Do not change product behavior merely to satisfy a stale test. First decide which contract is authoritative.

## 3. SQLite tests

Prove:

```text
fresh DB creation
migration ledger
foreign_keys enabled
WAL behavior
transaction rollback on failure
unsupported newer schema fail closed
corruption/integrity failure handling
concurrent writer busy handling
optimistic row-version conflict
```

## 4. Object tests

Prove:

```text
Host/Network/FQDN validation
multiple values
immutable ID rename behavior
reference preservation
reference-protected delete
Object Group membership
cycle rejection
context-invalid group assignment fails as a whole
Managed Host lifecycle remains under Managed Host commands
Managed Host references do not silently rebind to a different Agent identity
```

## 5. Endpoint address tests

Prove local inventory ingestion and membership calculation.

Reject/inactivate inappropriate loopback/link-local/multicast/special addresses from policy membership where required.

Test NAT/public observed source is not substituted for reported internal addresses.

## 6. Remote Service tests

Prove Agent-owned connectivity through the public Agent Host CLI:

```text
Agent Host + destination + Service Object -> Remote Service
TCP Remote Service works
Fixed TCP Remote Service works
UDP Remote Service is rejected with no mutation/allocation
another-host destination uses the current Agent Host as Relay Host
endpoint identity remains stable across restart and same-pool-class edits
valid unreachable target becomes DEGRADED rather than disappearing
```

Edit destination/Service Object and verify impact analysis.

## 7. Policy evaluator tests

For Remote Access and Internet Access separately:

```text
No Policy / No Rules -> effective ALLOW
BLACKLIST + matching enabled Rule -> DENY
BLACKLIST + no match -> ALLOW
WHITELIST + matching enabled Rule -> ALLOW
WHITELIST + no match -> DENY
disabled Rule does not match
Enforcement DISABLED -> effective ALLOW ALL while Mode/Rules are preserved
Policy Reset -> No Policy / No Rules / effective ALLOW
Rules have no ordering and no per-rule ALLOW/DENY action
```

## 8. Policy mode / enforcement mutation tests

Prove:

```text
BLACKLIST <-> WHITELIST mode change uses the documented reset semantics
Policy Reset removes Mode and Rules
Enforcement disable/enable preserves configured Mode/Rules
disabled Rule remains stored but ineffective
same desired state is idempotent
```

## 9. Policy-impact tests

For every referenced-entity class, create before/after expected effective behavior.

Required cases:

```text
Network Object value changes effective membership
Network Group member changes effective membership
Rule enable/disable changes effective access
Policy Mode / Enforcement change alters effective access
Remote Service destination/Service Object change alters effective connectivity/policy impact
Managed Host address membership changes destination membership
AI permission addition broadens
AI path scope expansion broadens
```

## 10. Runtime generation tests

Prove:

```text
DB revision -> compiled artifact revision
atomic activation
generation metadata persistence
compiler failure surfaced
generation mismatch surfaced
unsafe stale/missing generation fail closed
restart retains/verifies active generation
```

## 11. Backup/restore tests

Use the supported consistent snapshot mechanism.

Prove:

```text
backup under WAL activity
restore to clean install
schema/integrity validation
permissions/ownership
secrets/trust recovery
runtime regeneration from DB
revision/generation consistency
policy behavior identical after restore
```

Negative:

```text
truncated archive
corrupt DB
unsupported schema
missing required trust material
```

## 12. Internet Access security tests

Required deny regressions:

```text
unapproved source
unapproved FQDN
wrong port
loopback
RFC1918/private target where unsafe
link-local
metadata
IPv6 local/private where unsafe
IP-literal bypass
wildcard boundary bypass
DNS rebinding-style behavior
malformed CONNECT
CONNECT/SNI mismatch
unsafe ECH-dependent validation path
corrupt/missing current policy generation
```

Required allowed cases:

```text
approved HTTP
approved HTTPS CONNECT
approved public Host/CIDR where supported
approved Fixed TCP
```

## 13. Real application Internet Access

At minimum:

```text
curl
wget
git
apt
```

For `apt`, prove both:

```text
required destinations present → operation succeeds
required destination removed → operation fails through policy
```

Do not use broad wildcards merely to make the application test pass.

## 14. Remote Access Real E2E

Prove as applicable:

```text
SSH Remote Service
HTTP/HTTPS Remote Service
Custom TCP
Relay Host to another LAN destination
No Policy effective ALLOW
BLACKLIST deny match
WHITELIST allow match and non-match deny
Enforcement disable/enable behavior
established session not implicitly killed by policy edit
new connection uses new policy immediately
```

## 15. MCP protocol/interoperability validation

Immediately before implementation freeze, re-check the current official MCP specification and supported SDK behavior.

Do not treat legacy SSE-only behavior as the target if current clients support modern Streamable HTTP/current revision.

For each client claimed supported, record exact product/version and transport/auth method.

Target matrix:

```text
MCP_SPEC_VERSION=2026-07-28
OFFICIAL_SPEC_SOURCE=https://modelcontextprotocol.io/specification/2026-07-28/
REFERENCE_SDK=Python mcp 2.2.0 Streamable HTTP
ChatGPT=not claimed (no custom MCP developer surface in this environment)
Claude=not claimed (no remote custom connector UI/account in this environment)
Cursor=not claimed (this Cursor agent session has no remote HTTP MCP namespace; live host is Direct mode without a Data Relay Link 443 /mcp frontend)
Official SDK E2E=PASS (HTTPS /mcp through product frontend in tests)
```

A claim is not made merely because a generic MCP test client works.

## 16. MCP authentication tests

Prove:

```text
valid AI Identity succeeds only within policy
invalid credential denied
revoked credential denied
expired credential denied where applicable
disabled AI Identity denied
AI Identity attribution stable
authenticated transport required
```

## 17. MCP authorization tests

First prove AI Access policy semantics:

```text
AI authentication remains mandatory
No Policy / No Rules -> effective ALLOW after authentication
BLACKLIST matching enabled Rule -> DENY
BLACKLIST no match -> ALLOW
WHITELIST matching enabled Rule -> ALLOW
WHITELIST no match -> DENY
Enforcement DISABLED preserves Mode/Rules and yields policy ALLOW ALL
Rules have no ordering and no per-rule ALLOW/DENY action
```

Then for each required capability:

```text
exec
read_file
write_file
upload_file
download_file
```

prove ALLOW and DENY paths.

Also test target selection through:

```text
Network Object
Network Group
```

Unknown capability/tool => DENY.

## 18. MCP path-scope tests

Required cases:

```text
allowed file path
outside allowed path
../ traversal
absolute/relative normalization edge
symlink escape as applicable
upload destination outside scope
download outside scope
platform-specific path semantics
```

A path that cannot be proven within scope is denied.

## 19. MCP exec tests

Prove:

```text
allowed exec
denied exec
exec timeout
bounded output
process cleanup
OS account/sudo boundary
read-only role with exec=false
policy change affects next invocation
running command not implicitly killed by policy edit
```

## 20. MCP file transfer Real E2E

On a real private/closed endpoint:

```text
read known file
write allowed file
upload file
verify checksum/content
download file
verify checksum/content
attempt out-of-scope path -> DENY
```

Use disposable test data, not production secrets.

## 21. AI audit validation

Verify records contain:

```text
principal
target
tool
matched rule
result
duration
revision
safe metadata
```

Verify they do not contain raw credentials, full sensitive file contents, or unrestricted command output.

## 22. CLI/PTy validation

Protect:

```text
root domains
role filtering
root ?
help topics
help commands parity
Tab non-execution
context-valid Object suggestions
Managed Host / Network Object terms
Service Object Wizard preset terminology
BLACKLIST / WHITELIST Mode display
Enforcement state display
effective policy outcome
impact confirmation
stale-edit rejection
AI Identity secret safety
REPL vs shell hints
backend command isolation
```

## 22.1 ConfigurationBundle / AI-assisted configuration validation

Qualification must exercise the actual public CLI and the same installed control-plane engine used by ordinary operators.

Required automated + Real E2E cases:

```text
CONFIGURATION_BUNDLE_SCHEMA=PASS
CONFIGURATION_FILE_INPUT=PASS
CONFIGURATION_STDIN_INPUT=PASS
CONFIGURATION_VALIDATE_NO_MUTATION=PASS
CONFIGURATION_EMBEDDED_POLICY_TESTS=PASS
CONFIGURATION_DIFF=PASS
CONFIGURATION_IDEMPOTENT_REAPPLY_NO_CHANGE=PASS
CONFIGURATION_EXPLICIT_DELETE_ONLY=PASS
CONFIGURATION_REFERENCE_PROTECTION=PASS
CONFIGURATION_ATOMIC_ROLLBACK=PASS
CONFIGURATION_REVISION_CONFLICT=PASS
CONFIGURATION_SECURITY_IMPACT_CONFIRMATION=PASS
CONFIGURATION_REDACTED_EXPORT=PASS
CONFIGURATION_SECRET_EXCLUSION=PASS
DIRECT_CLI_AND_BUNDLE_SEMANTIC_PARITY=PASS
AI_COPY_PASTE_REAL_E2E=PASS
CLIENT_ACTION_REQUIRED_BOUNDARY=PASS
```

Semantic parity must compare equivalent changes made through direct CLI and ConfigurationBundle and prove they produce the same authoritative state/effective policy, impact decision, revision/audit semantics, and runtime behavior.

AI copy/paste Real E2E starts from a generated stdin block, applies it through the installed public `drlink` CLI, and verifies real traffic. Direct SQLite, JSON mutation, private helper commands, or hidden compatibility grammar cannot count as PASS.

Zero-Touch qualification:

```text
ZERO_TOUCH_MAX_10_PER_REQUEST=PASS
ZERO_TOUCH_MAX_10_ACTIVE_UNUSED=PASS
ZERO_TOUCH_CAPACITY_REMAINDER=PASS
ZERO_TOUCH_UNIQUE_PER_DEVICE=PASS
ZERO_TOUCH_SINGLE_USE=PASS
ZERO_TOUCH_CONCURRENT_DOUBLE_USE_DENY=PASS
ZERO_TOUCH_DEFAULT_TTL_1H=PASS
ZERO_TOUCH_MAX_TTL_24H=PASS
ZERO_TOUCH_EXPIRED_REVOKED_CAPACITY_RELEASE=PASS
ZERO_TOUCH_SECRET_DISPLAY_ONCE=PASS
ZERO_TOUCH_SERVER_STORES_NO_RAW_TICKET=PASS
ZERO_TOUCH_YAML_CANNOT_EMBED_SECRET=PASS
ZERO_TOUCH_LIMIT_CANNOT_BE_OVERRIDDEN=PASS
ZERO_TOUCH_EXPIRY_DOES_NOT_DISCONNECT_ENROLLED_CLIENT=PASS
```

Also prove that applying a bundle containing 30 enrollment plans issues 0 tickets and that explicit batch issuance never exceeds remaining active-unused capacity.

## 23. Version/governance transition validation

Before RC, tests that encode legacy MCP exclusion must be intentionally replaced.

Final governance proves:

```text
features.mcp_included=true for qualified v2.4.0 candidate
manifest schema permits/requires actual feature truth
no MCP_V2_4_EXCLUSION legacy guard
MCP inclusion qualification evidence present
exact source HEAD/ref immutable
no future-tag URL before tag exists
```

Do not change manifest feature truth to true until the candidate actually contains the qualified MCP implementation.

## 24. Fresh install / uninstall / reinstall

Prove:

```text
fresh server DB created
fresh client enrollment
no legacy JSON authority required
uninstall preserve-state behavior if supported
purge removes product-owned DB/runtime/secrets according to contract
reinstall creates/uses correct state
```

## 25. Upgrade/migration

Because v2.4.0 is pre-stable, backward compatibility with development JSON formats is not a public requirement.

Nevertheless, lab/test transition migration may be implemented for engineering convenience. It must not create dual authoritative state.

Final supported upgrade claims are based on actual prior stable releases and explicit migration code/evidence.

## 26. Multi-host matrix

Final applicable matrix:

```text
Ubuntu 24
Windows 10
Rocky Linux 8
Rocky Linux 9
Amazon Linux 2023
macOS Apple Silicon
```

Record qualification level honestly:

```text
code-only
container
system service
real VM/physical
field validated
stable supported
```

## 27. Full Real E2E pass 1

Record:

```text
FULL_REAL_E2E_PASS_1=PASS|FAIL
PASS1_HEAD=<40-char SHA>
```

It includes Remote Access + Internet Access + AI/MCP + lifecycle + backup/restore + supported platform matrix applicable to the release claim.

## 28. Full Real E2E pass 2

Repeat independently on the exact same HEAD:

```text
FULL_REAL_E2E_PASS_2=PASS|FAIL
PASS2_HEAD=<40-char SHA>
PASS1_HEAD==PASS2_HEAD
```

Any product/dependency/generated artifact change resets the count.

## 29. Evidence integrity

Retain enough evidence to verify:

```text
exact HEAD
build/artifact identity
commands/test suite version
platform
result
failure classification
release manifest/checksum
```

Do not claim PASS from memory or a different HEAD.

## 30. Final result format

```text
PHASE=V2_4_0_FINAL_RELEASE_QUALIFICATION
FINAL_STATUS=PASS|PARTIAL|FAIL
SOURCE_HEAD=
CONTROL_PLANE_DB=
NETWORK_OBJECT_MODEL=
NETWORK_GROUP_MODEL=
MANAGED_HOST_MODEL=
MANAGED_HOST_ADDRESS_INVENTORY=
REMOTE_SERVICE_MODEL=
REMOTE_ACCESS_POLICY_MODE=
INTERNET_ACCESS_POLICY_MODE=
AI_ACCESS_POLICY_MODE=
BLACKLIST_WHITELIST=
POLICY_ENFORCEMENT=
POLICY_RESET_SEMANTICS=
POLICY_IMPACT_ANALYSIS=
REFERENCE_PROTECTION=
CONCURRENT_EDIT_PROTECTION=
MCP_BRIDGE=
MCP_AUTH=
MCP_HOST_ROUTING=
MCP_CAPABILITY_ENFORCEMENT=
MCP_FILE_SCOPE=
MCP_AUDIT=
MCP_REAL_E2E=
CONFIGURATION_BUNDLE=
CONFIGURATION_DIRECT_CLI_PARITY=
CONFIGURATION_AI_COPY_PASTE_REAL_E2E=
ZERO_TOUCH_BOUNDED_BATCH=
SQLITE_MIGRATION_FRAMEWORK=
REVISION_AUDIT=
RUNTIME_GENERATION_CONSISTENCY=
BACKUP_RESTORE=
DB_CORRUPTION_FAIL_CLOSED=
MULTI_HOST_REAL_E2E=
FULL_REAL_E2E_PASS_1=
FULL_REAL_E2E_PASS_2=
PASS1_HEAD=
PASS2_HEAD=
UNRESOLVED_P0=
UNRESOLVED_P1=
UNRESOLVED_P2=
BLOCKERS=
```

PASS requires zero unresolved release-blocking findings and exact-HEAD evidence for every mandatory gate.

Recorded prior evidence and remaining platform limitations:

```text
REAL_ENTERPRISE_RESTRICTED_NETWORK_E2E=PASS
REAL_SSH_SERVICE_E2E=PASS
REAL_END_TO_END_REBOOT_RECOVERY=PASS
FIREWALL_DNAT_PRIVATE_FRP_SERVER=NOT_TESTED
REAL_ARM_SYSTEMD=NOT_TESTED
REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED
ROCKY_9_SELINUX_ENFORCING=NOT_TESTED
```
