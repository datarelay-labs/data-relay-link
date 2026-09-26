# Data Relay Link — User E2E Test Scenarios

> **Document role:** Canonical role-based User E2E execution matrix
> **Canonical path:** repository-root `USER_E2E_SCENARIOS.md` (single entry point; do not add a second copy under `docs/`)
> **Operator runbook:** Appendix A retains the v2.4 manual operator procedure
> **Product:** Data Relay Link
> **Target:** v2.4 and later until superseded
> **Primary CLI:** drlink
> **CLI/AI authority:** docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md
> **Release validation:** docs/RELEASE_VALIDATION.md
> **Release checklist:** docs/RELEASE_CHECKLIST.md
> **Status:** Normative living document

## 1. Purpose and execution trigger

This document defines the exhaustive real-user E2E suite for Data Relay Link.

When the user asks for any of the following without explicitly narrowing scope:

- 사용자 E2E
- 사용자 E2E 테스트
- Full User E2E
- User E2E
- 전체 E2E
- 전수 사용자 테스트

the default interpretation is:

~~~text
PROFILE=FULL_USER_E2E
RUN_ALL_MANDATORY_ROLE_SCENARIOS=YES
RUN_ALL_MANDATORY_SECURITY_NEGATIVE_SCENARIOS=YES
RUN_ALL_MANDATORY_PERFORMANCE_SCENARIOS=YES
USE_REAL_PUBLIC_PRODUCT_PATHS=YES
USE_ACTUAL_PUBLIC_DRLINK_CLI=YES
RETAIN_EVIDENCE=YES
~~~

A targeted E2E request may run a subset only when the user explicitly names the scope.

A release-qualification request uses this full suite plus the exact-HEAD double-pass rule in docs/RELEASE_VALIDATION.md.

### 1.1 User E2E execution ownership

FULL_USER_E2E is executed and independently evaluated by **ChatGPT**, not by Cursor.

This is a hard ownership rule:

~~~text
USER_E2E_EXECUTOR=ChatGPT
USER_E2E_FINAL_AUDITOR=ChatGPT
CURSOR_MAY_EXECUTE_FULL_USER_E2E=NO
CURSOR_MAY_DECLARE_USER_E2E_PASS=NO
~~~

Cursor may be used only after ChatGPT identifies an implementation defect or missing product behavior and the engineering workflow requires code changes.

The required loop is:

~~~text
ChatGPT
→ pin exact candidate HEAD/build
→ execute FULL_USER_E2E
→ collect evidence
→ identify/classify failures

If implementation change is required:
  ChatGPT
  → create/update the engineering Work Packet
  → hand the product fix to Cursor

Cursor
→ implement the requested fix
→ run implementation-level deterministic tests
→ report exact branch/HEAD/evidence

ChatGPT
→ independently verify the Cursor result
→ rerun every affected User E2E scenario
→ rerun any invalidated broader/full pass required by this document
→ make the final E2E PASS/PARTIAL/FAIL determination
~~~

Cursor-produced test output may be supporting evidence for implementation verification, but it does **not** substitute for ChatGPT's requested User E2E execution.

A Cursor session must never be treated as the executor of an unqualified request such as:

~~~text
사용자 E2E
사용자 E2E 테스트
Full User E2E
User E2E
전체 E2E
전수 사용자 테스트
~~~

If ChatGPT cannot execute a mandatory scenario because the real environment is unavailable, the result is `BLOCKED_ENVIRONMENT`; the scenario must not be delegated to Cursor merely to obtain PASS.

Historical PASS results, synthetic tests, unit tests, Docker-only results, Cursor-run results, or results from another Git HEAD do not replace a requested real User E2E run by ChatGPT.

If product code, dependencies, generated runtime artifacts, or the tested build changes during a full pass, record the new HEAD/build identity and invalidate the affected pass. For final release qualification, the double-pass counter resets as defined by the release validation policy.

## 2. Authority and conflict rules

Use this precedence when a scenario or command conflicts with another source:

1. actual tested behavior on the exact candidate build;
2. actual repository code and immutable Git state;
3. docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md;
4. docs/PRODUCT_MASTER.md;
5. docs/RELEASE_VALIDATION.md;
6. this document;
7. examples, screenshots, historical evidence.

This document defines what must be exercised. It does not redefine CLI grammar. If the CLI/AI Master changes, update this matrix in the same workstream.

## 3. Test roles

| Role | Test perspective | Normal responsibility |
| --- | --- | --- |
| User | Consumes a published service, approved Internet path, or approved AI capability | Connect, transfer data, use applications, observe allow/deny behavior |
| Operator | Operates an Agent Host and Remote Services day to day | Enrollment execution, Remote Service lifecycle, Agent lifecycle, local configuration, diagnostics |
| Administrator | Operates the Data Relay Link Server and security/control state | Managed Hosts, Objects/Groups, Access Policies, AI Identity/permissions, audit, revision, backup/restore, server lifecycle |
| External load generator | Performance-only actor | Throughput, CPS, concurrency, latency, full-duplex, churn, soak |
| Target service | Real destination behind an Agent/Relay Host or on the Internet | SSH/HTTP/HTTPS/Custom TCP/Fixed TCP/application behavior |

The same person may perform more than one role, but evidence must identify which role and host executed each step.

## 4. Test profiles

### 4.1 FULL_USER_E2E

FULL_USER_E2E is the default for an unqualified User E2E request.

It includes:

- all U-* user scenarios marked MANDATORY;
- all O-* operator scenarios marked MANDATORY;
- all A-* administrator scenarios marked MANDATORY;
- all S-* security/failure scenarios marked MANDATORY;
- all P-* performance scenarios marked MANDATORY;
- every applicable supported platform in the current release claim;
- real external clients and real application traffic;
- allow and deny validation;
- lifecycle, reboot, update, backup/restore, and recovery;
- exact command and evidence capture.

### 4.2 TARGETED_USER_E2E

Use only when the user explicitly narrows scope, for example:

~~~text
SSH만 사용자 E2E
Internet Access만 E2E
Windows Agent만 E2E
성능만 E2E
~~~

Record omitted scenario IDs as NOT_RUN_BY_SCOPE, never PASS.

### 4.3 RELEASE_QUALIFICATION

Run FULL_USER_E2E twice on the same exact HEAD when the release validation requires double Full Real E2E.

~~~text
PASS1_HEAD == PASS2_HEAD == FINAL_QUALIFIED_HEAD
~~~

Any qualifying product/dependency/generated-artifact change resets the release pass counter.

## 5. Required topology and environment

Use disposable or explicitly designated test systems for destructive scenarios.

Minimum full topology:

~~~text
External User / Load Generator
        |
        v
Public Data Relay Link endpoint
        |
        v
Data Relay Link Server
        |
        +------------------------+
        |                        |
        v                        v
Direct Agent Host          Relay Agent Host
(local target)             (gateway)
                                 |
                                 v
                           LAN target without Agent

Restricted/Protected Host
        |
        v
Internet Access path
        |
        v
Approved public Internet destination

AI client / MCP client, when included in the tested candidate
        |
        v
Data Relay Link AI/MCP frontend
        |
        v
Authorized Managed Host/path
~~~

Full test evidence must record:

~~~text
TEST_RUN_ID=
START_UTC=
END_UTC=
REPOSITORY=
BRANCH=
SOURCE_HEAD=
WORKTREE_OR_ARTIFACT=
PRODUCT_VERSION=
RELEASE_CHANNEL=
RELAY_ENGINE_VERSION=
CONTROL_DB_SCHEMA_VERSION=
SERVER_OS=
SERVER_ARCH=
SERVER_PUBLIC_IP=
SERVER_PUBLIC_HOSTNAME=
SERVER_TOPOLOGY=
AGENT_HOSTS=
RELAY_HOSTS=
TARGET_HOSTS=
EXTERNAL_CLIENTS=
INTERNET_ACCESS_CLIENTS=
AI_CLIENTS=
~~~

Before testing, capture the exact build identity from the installed product, not only from Git.

## 6. Common preflight

### 6.1 Server preflight

Run through the public Server CLI:

~~~text
show status
system status
system version
system diagnostics
system audit
show managed-hosts
show remote-access
show internet-access
show ai-identities
show ai-access
~~~

Expected:

- role is DRLink Server;
- product/source version is the expected candidate;
- no unexplained DEGRADED or unsafe generation state;
- diagnostics are read-only;
- no secrets are emitted.

### 6.2 Agent Host preflight

Run locally on each Agent Host:

~~~text
show status
show agent
show remote-services
system info
system version
system diagnostics
~~~

Expected:

- role is Agent Host;
- correct Managed Host identity;
- expected Server connection state;
- no unexpected endpoint drift;
- no secret leakage.

### 6.3 CLI invocation form

Inside the persistent CLI, use commands exactly as documented:

~~~text
drlink> show status
drlink> show managed-hosts
~~~

From a shell, prefix the same public command with the installed executable, normally:

~~~text
sudo drlink show status
sudo drlink show managed-hosts
~~~

Do not substitute private backend commands, direct SQLite mutation, hidden compatibility commands, or internal FRP helper CLIs for a User E2E PASS.

### 6.4 CLI-only hard gate

All Data Relay Link control-plane, configuration, lifecycle, diagnostics, recovery, and inspection actions in FULL_USER_E2E must be performed through the public `drlink` CLI.

The following may not be used to obtain or repair a PASS:

- direct SQLite/DB access or mutation;
- direct JSON/state-file mutation;
- private Python/module entry points;
- internal FRP helper CLIs;
- private HTTP/REST management APIs;
- Web UI management paths;
- hidden compatibility grammar when a canonical public command exists;
- editing generated runtime configuration behind DRLink.

Real data-plane clients are still required to prove real behavior. Examples include `ssh`, `scp`, `curl`, `wget`, `git`, `apt`, a real TCP load generator, and a supported MCP client. These clients may generate or consume traffic, but all DRLink state changes and observations used for PASS must remain through `drlink`.

AI may generate commands or ConfigurationBundles, but AI is an input assistant only. The generated result must be executed, tested, diffed, applied, inspected, and recovered through the public `drlink` CLI. AI must never obtain a PASS by directly changing product state.

Required aggregate gate:

~~~text
DRLINK_CONTROL_PLANE_CLI_ONLY=PASS
PRIVATE_BACKEND_MUTATION_USED=NO
DIRECT_DB_MUTATION_USED=NO
PRIVATE_MANAGEMENT_API_USED=NO
~~~

### 6.5 CLI surface parity and 100% command execution

FULL_USER_E2E must exercise all applicable public CLI surfaces, not merely list them:

- shell one-shot form;
- persistent `drlink>` REPL;
- guided menu;
- Guided Create/Edit Wizard;
- `?`;
- `help` and applicable help topics;
- Tab completion and non-execution safety;
- file ConfigurationBundle input;
- stdin ConfigurationBundle input.

Every public command family listed in section 14 must map to at least one executed scenario and current-run evidence.

Required gate:

~~~text
PUBLIC_CLI_COMMAND_COVERAGE=100%
PUBLIC_CLI_SURFACE_COVERAGE=100%
UNEXERCISED_PUBLIC_COMMANDS=0
~~~

Commands that are genuinely not applicable to the tested role/platform must be listed individually with a reason; they may not silently disappear from coverage.

### 6.6 Parallel execution rules

Independent scenario lanes should run in parallel when doing so does not destroy shared state needed by another lane. Use unique test prefixes for Objects, Rules, Remote Services, enrollment records, files, and AI identities so parallel tests cannot collide accidentally.

Serial execution is allowed only where the test intentionally mutates shared global state, for example:

- Server-wide policy reset;
- Server restore/rollback;
- Server uninstall/reinstall;
- global endpoint-pool exhaustion;
- release-wide update;
- a deliberate concurrency/race test that coordinates multiple writers.

Parallel execution must never weaken evidence isolation. Every command/result must identify the host, role, scenario, and timestamp.

### 6.7 AI and ChatGPT Plugin boundary

AI-assisted CLI is mandatory in core FULL_USER_E2E, but the optional ChatGPT Plus Plugin/relay is a separate repository and integration surface.

Core rule:

~~~text
AI generates intent/command/Bundle
→ operator executes through public drlink CLI
→ drlink remains the only DRLink management/configuration authority used by the E2E
~~~

The optional repository `datarelay-labs/datarelay-link-plugin` is an experimental ChatGPT Plus / Agent Plugins + MCP relay layer. A real ChatGPT Plugin acceptance test therefore cannot be represented as a pure `drlink` CLI interaction end to end.

If the requested E2E scope includes the Plugin stack:

- pin the exact Plugin repository HEAD separately;
- keep all DRLink configuration/policy/identity setup through `drlink`;
- exercise Plugin/relay transport only for its actual data-plane/authentication role;
- verify the relay does not invent tools, cache authorization decisions, or reinterpret DRLink AI Access;
- verify DRLink remains the final authorization source on every tool call;
- report Plugin acceptance separately from core CLI coverage.

A Plugin failure must not be hidden by a passing direct MCP client, and a Plugin PASS must not be used as evidence that the core public CLI commands were exercised.

# 7. User scenarios

## U-001 — Published SSH service — MANDATORY

Goal: prove an external user can use a real SSH service through Data Relay Link.

Preparation on Server, if objects are not already present:

~~~text
set service-object ssh type tcp port 22
~~~

On the Agent Host:

~~~text
set remote-service ssh-access destination this-host service ssh enabled
show remote-service ssh-access
~~~

On Server:

~~~text
show managed-host <HOST> remote-services
test remote-access source <SOURCE> destination <HOST> service ssh
~~~

From the external user host, connect to the actual Endpoint returned by DRLink:

~~~text
ssh -p <PUBLIC_PORT> <USER>@<PUBLIC_HOST>
~~~

Verify:

- successful authentication through the real public endpoint;
- interactive command execution;
- upload and download through SSH/SCP/SFTP where available;
- Remote Service reports HEALTHY;
- Server and Agent show the same endpoint;
- no direct private-IP bypass is counted as PASS.

## U-002 — HTTP, HTTPS, and Custom TCP services — MANDATORY

Create/reuse TCP Service Objects and create Agent-owned Remote Services.

Examples:

~~~text
set service-object http type tcp port 80
set service-object https type tcp port 443
set service-object app-tcp type tcp port <TARGET_PORT>
~~~

Agent Host:

~~~text
set remote-service http-access destination this-host service http enabled
set remote-service https-access destination this-host service https enabled
set remote-service app-access destination this-host service app-tcp enabled
show remote-services
~~~

External client verification:

- HTTP request returns expected application content;
- HTTPS passthrough preserves end-to-end application TLS and certificate behavior;
- Custom TCP transfers application data in both directions;
- wrong endpoint/port does not accidentally reach another target.

Use real application clients where practical, not only a TCP connect probe.

## U-003 — Remote Access policy from the user perspective — MANDATORY

Exercise all effective states against a real published service.

No Policy:

~~~text
unset remote-access policy
test remote-access source <SOURCE> destination <HOST> service ssh
~~~

Verify effective ALLOW and successful real connection.

BLACKLIST first rule:

~~~text
set remote-access block-user mode blacklist source <SOURCE> destination <HOST> service ssh enabled
test remote-access source <SOURCE> destination <HOST> service ssh
~~~

Verify matching source is DENY and a non-matching source remains ALLOW.

Reset and WHITELIST first rule:

~~~text
unset remote-access policy
set remote-access allow-user mode whitelist source <SOURCE> destination <HOST> service ssh enabled
test remote-access source <SOURCE> destination <HOST> service ssh
~~~

Verify matching source is ALLOW and a non-matching source is DENY.

Also verify:

~~~text
set remote-access disabled
set remote-access enabled
~~~

Enforcement disable must preserve Mode/Rules and temporarily yield effective ALLOW ALL according to the canonical policy contract.

## U-004 — Relay Host to another LAN destination — MANDATORY

On a Relay Agent Host, create a Remote Service whose destination is another host.

~~~text
set remote-service lan-target-service destination <TARGET_OBJECT> service <SERVICE_OBJECT> enabled
show remote-service lan-target-service
~~~

Server:

~~~text
show managed-host <RELAY_HOST> remote-services
~~~

External user connects to the returned public Endpoint.

Verify:

- current Agent Host is the Relay Host;
- target host does not require a DRLink Agent;
- real application traffic succeeds;
- temporary target outage changes status to DEGRADED without losing the endpoint reservation;
- recovery returns to HEALTHY without recreation.

## U-005 — Fixed TCP user path — MANDATORY

Server:

~~~text
set service-object fixed-app type fixed-tcp port <TARGET_PORT>
~~~

Relay/Agent Host:

~~~text
set remote-service fixed-app-access destination <DESTINATION> service fixed-app enabled
show remote-service fixed-app-access
~~~

Verify real bidirectional application traffic through the allocated Fixed TCP endpoint.

Also prove the Fixed TCP pool is distinct from the normal Remote Service pool.

## U-006 — Internet Access real applications — MANDATORY

Create/reuse Network and Service Objects and an Internet Access WHITELIST rule.

Typical administrative commands:

~~~text
set network-object approved-site
set service-object https
set internet-access approved-https mode whitelist source <SOURCE> destination approved-site service https enabled
test internet-access source <SOURCE> destination approved-site service https
~~~

From the protected host, use real applications as applicable:

~~~text
curl
wget
git
apt
~~~

Verify:

- approved destination/port works;
- unapproved destination fails;
- wrong destination port fails;
- removing a destination required by an application makes that application fail through policy;
- broad wildcard expansion is not used just to obtain PASS.

## U-007 — AI/MCP authorized and denied use — MANDATORY when candidate includes AI/MCP

Server creates/binds the AI Identity using the supported authentication workflow, then configures permissions and AI Access.

Representative CLI:

~~~text
set ai-identity <IDENTITY>
set permission-object read-only permissions host-info,process-read,file-read
set ai-access ai-read mode whitelist source <IDENTITY> destination <DESTINATION> permission read-only enabled
test ai-access source <IDENTITY> destination <DESTINATION> permission read-only
show ai-access-log identity <IDENTITY>
~~~

From the supported AI/MCP client, verify:

- valid authenticated identity succeeds only inside policy;
- invalid/revoked/expired credentials are denied;
- allowed host-info/process-read/file-read succeeds;
- disallowed exec/write/upload/download is denied for read-only permission;
- path-scope traversal and symlink escape attempts are denied where applicable;
- audit attribution identifies principal, target, tool, result, revision, and safe metadata;
- no raw credentials or sensitive file contents leak into audit.

If AI/MCP is explicitly excluded from the candidate being tested, record this scenario NOT_APPLICABLE with exact feature evidence. Do not silently skip it.

## U-008 — User continuity across restart and policy change — MANDATORY

With an active Remote Service:

1. record endpoint;
2. restart Agent;
3. restart Server as applicable;
4. verify endpoint reservation is unchanged;
5. establish a session;
6. change policy;
7. verify existing-session semantics match the release contract;
8. verify the next new connection uses the new policy immediately.

Record endpoint before/after and real traffic result.

## U-009 — Public hostname, public IP fallback, and Zero-Touch URL propagation — MANDATORY

When a public DNS hostname is configured, verify entirely through the public CLI workflow that:

- Enrollment HTTPS output uses the configured public hostname;
- Zero-Touch bootstrap output uses the configured public hostname;
- the short launcher remains short and preserves private-CA fingerprint and one-time-ticket security;
- public IP is shown only as the supported fallback/alternative, not as an unexplained replacement for the configured hostname;
- Remote Service endpoint presentation uses the configured public hostname where the current product contract says it should;
- clearing an optional hostname returns to the documented default/fallback behavior.

Execute the generated bootstrap path from a real external test host and verify DNS, TLS, enrollment, and final Remote Service usability end to end.

## U-010 — Guided CLI user journey parity — MANDATORY

Perform at least one complete onboarding/configuration journey through the guided CLI rather than only one-shot commands.

Exercise:

~~~text
drlink
menu
?
help
Tab
Guided Create/Edit Wizard
Review
Apply
Cancel
Back
Exit
~~~

Repeat the same intent using canonical direct CLI and verify equivalent final authoritative state and effective behavior.

The guided flow must not require knowledge of hidden backend commands, must not repeat already-collected identification unnecessarily, and invalid input must keep the user on the correct step with prior valid draft values preserved.

## U-011 — AI/MCP capability matrix and file transfer — MANDATORY when candidate includes AI/MCP

Configure AI Identity, target, Permission Objects/Groups, and AI Access only through the Server CLI.

For each capability exposed by the current candidate, prove both ALLOW and DENY paths:

~~~text
host-info
process-read
file-read
command-exec
file-write
file-upload
file-download
~~~

Real E2E must include, where supported:

- read a known disposable file;
- write an allowed disposable file;
- upload a file and verify checksum/content;
- download it and verify checksum/content;
- attempt out-of-scope/traversal/symlink escape -> DENY;
- allowed exec;
- denied exec;
- exec timeout;
- bounded output;
- process cleanup;
- OS account/sudo boundary;
- policy change affects the next invocation;
- a running command/session follows the documented existing-session semantics.

Target selection must be exercised through both a direct Network Object and a Network Group where supported.

## U-012 — Internet Access protocol/application coverage — MANDATORY

In addition to U-006, explicitly exercise every currently supported Internet Access data path claimed by the candidate:

- approved HTTP;
- approved HTTPS CONNECT;
- approved public Host/CIDR where supported;
- approved Fixed TCP where supported;
- representative vendor/API HTTPS;
- real package/update workflow.

For each allowed path include a paired denied path using wrong source, destination, or port.

# 8. Operator scenarios

## O-001 — First-use discovery and role correctness — MANDATORY

Agent Host:

~~~text
show status
show agent
show remote-services
system info
system version
~~~

Verify role-aware help/menu and that Server-only mutation commands return a clear role error rather than Unknown command.

## O-002 — Zero-Touch enrollment — MANDATORY

Server:

~~~text
set enrollment zero-touch
show enrollments
show enrollment <ENROLLMENT>
~~~

Run the generated bootstrap command on a clean supported Agent Host exactly as presented.

Verify:

- ticket is displayed according to the current secret-display contract;
- TLS verification is not weakened;
- single-use behavior;
- first machine binding;
- enrolled Managed Host appears;
- expiry/revocation semantics;
- successful enrollment is not disconnected merely because the ticket later expires;
- an initial Remote Service seeded by bootstrap is not reported HEALTHY merely because its local target socket is reachable;
- before real relay/proxy verification, the seeded service remains truthfully DEGRADED/runtime-pending;
- after actual relay verification succeeds, the same service/endpoint transitions to HEALTHY without endpoint identity drift.

## O-003 — Manual and bulk enrollment — MANDATORY

Server:

~~~text
set enrollment manual
set enrollment bulk
show enrollments
~~~

Verify issuance limits/capacity, unique per-device material where required, revocation, and terminal-record lifecycle.

Cleanup:

~~~text
unset enrollment <ENROLLMENT>
~~~

## O-004 — Remote Service lifecycle — MANDATORY

Agent Host:

~~~text
show remote-services
set remote-service <NAME>
show remote-service <NAME>
set remote-service <NAME> disabled
set remote-service <NAME> enabled
unset remote-service <NAME>
~~~

Verify:

- create/edit uses one Service Object;
- UDP is rejected for Remote Service;
- same effective destination+service duplicate is rejected;
- disable preserves endpoint;
- enable reuses endpoint;
- same-pool destination/service edit preserves endpoint;
- TCP <-> Fixed TCP in-place cross-pool edit is rejected;
- delete eventually releases endpoint reservation.

## O-005 — Server outage, offline Agent edit, and synchronization — MANDATORY

With synchronized local metadata, make the Server temporarily unreachable.

Agent Host:

~~~text
set remote-service offline-created destination this-host service ssh enabled
show remote-service offline-created
~~~

Expected for a new service:

~~~text
Status   : DEGRADED
Endpoint : Pending allocation
~~~

Restore Server connectivity and verify synchronization, allocation, activation, and HEALTHY transition without recreating the service.

When diagnostics recommend it, the public recovery command must parse:

~~~text
system synchronize
~~~

For an existing service, verify the previously allocated endpoint remains unchanged across the outage.

## O-006 — Agent lifecycle — MANDATORY

~~~text
system pause
show status
system resume
show status
system restart
show status
system autostart disable
system autostart enable
~~~

Verify deliberate pause/disable state is distinguishable from DEGRADED failure state and that state recovers correctly.

## O-007 — Agent ConfigurationBundle file/stdin — MANDATORY

Read-only validation:

~~~text
test configuration <FILE>
test configuration -
~~~

Diff:

~~~text
system diff configuration <FILE>
system diff configuration -
~~~

Apply:

~~~text
system apply configuration <FILE>
system apply configuration -
~~~

Export:

~~~text
system export configuration <FILE>
~~~

For stdin, terminate the pasted YAML using the canonical :end workflow.

Verify:

- test and diff do not mutate;
- apply revalidates current state;
- invalid last resource leaves no earlier resource behind;
- same bundle reapply returns NO CHANGE;
- export excludes real secrets;
- Agent bundle cannot mutate Server policy.

## O-008 — Diagnostics and support bundle — MANDATORY

~~~text
system diagnostics
system support-bundle
system version
~~~

Verify support output identifies Agent Host role, includes useful provenance, and does not expose raw credentials, tokens, private keys, or ambiguous unknown digests.

## O-009 — Product update and Relay Engine update separation — MANDATORY

Agent Host:

~~~text
system update product
system update engine
system version
~~~

Verify product and upstream engine versions remain separate, update does not require ordinary re-enrollment, and endpoint/identity/state are preserved.

## O-010 — Reboot/autostart recovery — MANDATORY

Reboot each applicable Agent Host.

After reboot:

~~~text
show status
show agent
show remote-services
system diagnostics
~~~

Verify automatic service start, identity continuity, endpoint continuity, and real external traffic.

## O-011 — Agent uninstall/reinstall behavior — MANDATORY on disposable host

~~~text
system uninstall
~~~

Verify interactive CLI exits cleanly after successful removal.

Reinstall according to the supported candidate path and verify the documented preserve/re-enroll semantics. Do not infer server-side release of reservations unless the product explicitly performs it.

## O-012 — Wrong-context commands — MANDATORY

On Agent Host:

~~~text
set remote-access bad-context
set internet-access bad-context
~~~

Expected: clear instruction to run on the DRLink Server and no mutation.

On Server:

~~~text
set remote-service bad-context
~~~

Expected: clear instruction to run on the owning Agent Host and no mutation.

## O-013 — AI-assisted one-resource CLI loop — MANDATORY

Use an AI assistant to express a real user intent as one complete public CLI command.

Required flow:

~~~text
user intent
→ AI generates one canonical drlink command
→ operator pastes into drlink
→ CLI validates/reviews/applies
→ operator verifies through show/test
→ real traffic verifies behavior
~~~

Then deliberately provide a missing dependency so the CLI returns a copy-back-safe error. Give that error back to the AI and require a corrected command or a recommendation to use ConfigurationBundle.

Verify:

- the AI does not require hidden database IDs;
- the AI does not use private backend commands;
- an incomplete new Resource is rejected atomically;
- an existing Resource partial edit changes only supplied fields;
- generated shell metacharacters cannot bypass CLI shell-safety rules.

## O-014 — AI-assisted multi-resource ConfigurationBundle loop — MANDATORY

Use AI to generate a multi-resource ConfigurationBundle.

Required flow:

~~~text
AI-generated Bundle
→ test configuration -
→ :end
→ system diff configuration -
→ system apply configuration -
→ show/test verification
→ real traffic verification
~~~

Also execute:

- same Bundle reapply -> NO CHANGE;
- Test Bundle A, then Apply different Bundle B -> B is independently revalidated;
- export current configuration -> give redacted export to AI -> AI modifies only requested public state -> test/diff/apply;
- invalid final Resource -> no earlier Resource remains;
- cross-context request -> AI returns separate Agent and Server operations, never a fake distributed atomic transaction.

All DRLink mutations remain CLI-only.

## O-015 — Wizard draft/cancel/invalid-input atomicity — MANDATORY

Through the guided CLI:

1. begin creating a Rule;
2. create a draft inline Object;
3. enter an invalid value at a later step;
4. verify the Wizard remains on the same step and preserves earlier valid draft input;
5. Cancel the parent Wizard;
6. verify the inline draft Object does not exist.

Also test Back/Cancel from representative Server and Agent workflows. No cancelled draft may allocate an endpoint, create a Resource, increment authoritative configuration unexpectedly, or leave a runtime artifact.

# 9. Administrator scenarios

## A-001 — Managed Host inventory and lifecycle — MANDATORY

~~~text
show managed-hosts
show managed-host <HOST>
show managed-host <HOST> agent
show managed-host <HOST> addresses
show managed-host <HOST> remote-services
unset managed-host <HOST>
~~~

Verify removal is reference-safe and displays impact before destructive cleanup.

## A-002 — Network Objects and Groups — MANDATORY

~~~text
show network-objects
show network-object <OBJECT>
show network-object <OBJECT> references
show network-groups
show network-group <GROUP>
show network-group <GROUP> references

set network-object <OBJECT>
set network-group <GROUP>

unset network-object <OBJECT>
unset network-group <GROUP>
~~~

Exercise IP, CIDR, FQDN, Managed Host selector use, group membership changes, invalid input, ambiguity, and reference-safe deletion.

## A-003 — Service Objects and Groups — MANDATORY

~~~text
show service-objects
show service-object <SERVICE>
show service-object <SERVICE> references
show service-groups
show service-group <GROUP>
show service-group <GROUP> references

set service-object <SERVICE>
set service-group <GROUP>

unset service-object <SERVICE>
unset service-group <GROUP>
~~~

Exercise TCP, UDP, and Fixed TCP object types.

Verify UDP may exist at the object layer but is rejected from Remote Service and Remote Access uses that do not support it.

## A-004 — Remote Access full policy lifecycle — MANDATORY

~~~text
show remote-access
show remote-access <RULE>
set remote-access <RULE>
set remote-access enabled
set remote-access disabled
unset remote-access <RULE>
unset remote-access policy
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
~~~

Verify:

- first human rule selects BLACKLIST/WHITELIST;
- first one-shot rule requires mode;
- matching and non-matching behavior;
- disabled Rule does not match;
- deleting last rule preserves Mode;
- last WHITELIST rule removal yields DENY ALL;
- last BLACKLIST rule removal yields ALLOW ALL;
- policy reset removes Mode and Rules and returns No Policy / ALLOW;
- direct BLACKLIST <-> WHITELIST conversion is not silently performed.

## A-005 — Internet Access full policy lifecycle and security — MANDATORY

~~~text
show internet-access
show internet-access <RULE>
set internet-access <RULE>
set internet-access enabled
set internet-access disabled
unset internet-access <RULE>
unset internet-access policy
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
~~~

Exercise real traffic plus all mandatory security-negative cases in section 10.

## A-006 — AI Identity, permissions, AI Access, and logs — MANDATORY when feature included

~~~text
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

set ai-identity <IDENTITY>
set permission-object <PERMISSION>
set permission-group <GROUP>
set ai-access <RULE>
set ai-access enabled
set ai-access disabled

unset ai-identity <IDENTITY>
unset permission-object <PERMISSION>
unset permission-group <GROUP>
unset ai-access <RULE>
unset ai-access policy

test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
~~~

Verify authentication and authorization remain separate, reference-safe deletion works, and disabling AI Access policy enforcement does not bypass AI authentication.

## A-007 — Reference protection — MANDATORY

Attempt to delete referenced Network Object, Network Group, Service Object, Service Group, Permission Object/Group, AI Identity, and referenced Managed Host.

Expected:

- deletion rejected;
- references listed;
- no partial mutation;
- remove/change references first, then deletion succeeds.

## A-008 — Revisions, diff, audit, and rollback — MANDATORY

~~~text
system revisions
system revision <REVISION>
system diff <REVISION_A> <REVISION_B>
system audit
system rollback <REVISION>
~~~

Verify revision history, diff correctness, audit attribution, rollback safety, runtime generation consistency, and real traffic after rollback.

## A-009 — Backup and restore — MANDATORY on disposable environment

~~~text
system backup
system restore <FILE>
system diagnostics
~~~

Restore into the supported clean/recovery topology.

Verify preservation of:

- trust/PKI;
- Managed Host identity;
- Remote Services and endpoint reservations;
- Objects/Groups;
- all policy families;
- AI identity metadata and safe secrets/trust handling;
- revisions/generation consistency;
- real Remote Access and Internet Access behavior after restore.

Also execute corrupt/truncated/unsupported restore negatives in S-010.

## A-010 — Server ConfigurationBundle atomicity and parity — MANDATORY

~~~text
test configuration <FILE|->
system diff configuration <FILE|->
system apply configuration <FILE|->
system export configuration <FILE>
~~~

Verify:

- direct CLI and equivalent Bundle reach the same authoritative state/effective policy;
- file and stdin inputs work;
- invalid final resource causes zero earlier mutations;
- same Bundle reapply is NO CHANGE;
- missing resource means unchanged unless state: absent is explicit;
- export omits authentication secrets;
- security-impact confirmation is based on the actual Bundle being applied, not on a previously tested different Bundle.

## A-011 — Server system operations — MANDATORY

~~~text
system status
system version
system diagnostics
system audit
system certificate
system update
system support-bundle
~~~

Verify stable/preview/development identity and exact Source HEAD are truthful, certificate state is coherent, diagnostics are read-only, update follows candidate/release rules, and support output is secret-safe.

## A-012 — Zero-Touch capacity and credential security — MANDATORY

Verify the current limits and security contracts through real Server CLI workflows, including:

- maximum issuance per request;
- maximum active unused capacity;
- remaining-capacity handling;
- unique per-device ticket;
- single use;
- concurrent double redemption denied;
- default TTL;
- maximum TTL;
- expired/revoked ticket releases capacity;
- secret displayed only according to contract;
- Server does not retain raw ticket;
- ConfigurationBundle cannot embed ticket secret or bypass lifecycle;
- expiry does not disconnect an already enrolled host.

Use the current authoritative limits from the CLI/AI Master and release validation at execution time.

## A-013 — Endpoint pools and allocation lifecycle — MANDATORY

Exercise normal Remote Service and Fixed TCP pools.

Verify:

- pools do not overlap;
- existing reservation is never stolen;
- create allocates from correct pool;
- disable/restart/disconnect preserves reservation;
- delete releases reservation;
- cross-pool in-place edit is rejected;
- configured pool exhaustion returns a truthful error or DEGRADED/Pending allocation according to whether allocation was available at apply time;
- later available capacity allows expected recovery.

## A-014 — Concurrent/stale administrative change protection — MANDATORY

Using two administrator sessions, attempt conflicting edits to the same authoritative configuration/revision.

Verify stale edit/revision conflict is surfaced, no last-writer corruption occurs, and subsequent state/audit is deterministic.

## A-015 — Fresh Server install / uninstall / reinstall — MANDATORY on disposable server

Prove:

- fresh Server state initializes correctly;
- no hidden legacy authority is required;
- uninstall/preserve behavior matches the documented contract;
- purge/destructive removal, when supported and explicitly selected, removes only product-owned state according to contract;
- reinstall creates or restores the correct authoritative state;
- real User E2E traffic is revalidated after recovery.

## A-016 — AI workflow and CLI traceability audit — MANDATORY

At the end of FULL_USER_E2E, produce a machine-readable or clearly auditable mapping:

~~~text
PUBLIC_CLI_COMMAND -> SCENARIO_ID -> HOST/ROLE -> RESULT -> EVIDENCE
~~~

Every applicable command in section 14 must have at least one current-run execution record.

Separately map every canonical CLI/AI Master scenario relevant to the current candidate, including:

- first run/no-policy;
- Zero-Touch + direct SSH;
- BLACKLIST;
- WHITELIST reconstruction;
- policy enforcement disable/re-enable;
- inline Object creation then Cancel;
- unreachable Relay destination;
- Fixed TCP;
- cross-pool rejection;
- UDP rejection;
- Internet Access Managed Host source and invalid Managed Host destination;
- AI Identity/AI Access;
- AI one-shot;
- missing dependency;
- Server and Agent ConfigurationBundle;
- cross-context AI request;
- final-Resource Bundle failure;
- idempotent reapply;
- test A/apply B;
- Export -> AI -> Reapply;
- referenced Object deletion;
- last Rule semantics;
- runtime activation rollback;
- Server-unreachable Remote Service create;
- Agent disconnect/reconnect;
- role mistakes.

No canonical scenario may be omitted merely because a similar scenario passed.

## A-017 — Concurrent administrative writers — MANDATORY

Use multiple public CLI administrator sessions.

Exercise:

- two conflicting edits based on the same prior revision;
- two non-conflicting changes where the product supports safe serialization;
- one Bundle apply racing with a direct CLI mutation;
- one rollback/restore attempt while another mutation is pending, according to supported locking behavior.

Expected:

- stale/current-state conflict is detected or safely serialized;
- no lost update;
- no DB/runtime corruption;
- no partial generation;
- audit/revision order remains explainable;
- CLI remains responsive after contention.

## A-018 — Public hostname/bootstrap configuration lifecycle — MANDATORY

Using only public Server CLI, exercise set/change/clear behavior for public/bootstrap hostname configuration supported by the candidate.

After each change, regenerate or inspect:

- Enrollment endpoint;
- Zero-Touch short URL;
- Remote Service endpoint presentation where applicable;
- diagnostics/version/support evidence.

Verify no change to an optional friendly hostname silently changes control/allocator identity unless the current product contract explicitly says so.

## A-019 — Prior-stable upgrade to candidate — MANDATORY when an upgrade path is claimed

On each applicable real platform, start from the actual currently supported prior stable release and update using only the supported public CLI/install path.

Verify:

- Managed Host identity preserved;
- enrollment/trust preserved unless the documented migration explicitly requires otherwise;
- Service/Remote Service identity preserved;
- endpoint/public-port reservations preserved;
- Objects/Groups/Policies preserved or migrated deterministically;
- backup remains restorable;
- product and Relay Engine versions remain distinct;
- no hidden legacy state becomes a second authority;
- reboot after upgrade succeeds;
- real Remote Access and Internet Access traffic succeeds after upgrade.

Historical upgrade evidence from another HEAD does not satisfy the current requested run.

## A-020 — Update failure and recovery — MANDATORY on disposable environment

Initiate the supported product update through public CLI and inject/observe representative failures such as unavailable artifact, integrity mismatch, activation failure, or restart failure where the harness can safely reproduce them.

Verify:

- failed update is not reported as success;
- old working state is preserved/restored where the update contract promises atomic recovery;
- identity and endpoint reservations are not silently recreated;
- operator receives actionable diagnostics;
- retry after the blocker is corrected converges to a healthy supported state.

If downgrade is unsupported, an attempted downgrade must be rejected explicitly rather than silently performing an unsafe transition.

# 10. Security and failure scenarios

## S-001 — Allow and deny are both proven — MANDATORY

Every policy family tested must include a real ALLOW and real DENY path. A successful allowed flow alone cannot pass security E2E.

## S-002 — Invalid configuration is atomic — MANDATORY

Use invalid/missing Object references, invalid CIDR/FQDN/ports, unsupported UDP Remote Service, wrong Bundle context, incomplete one-shot command, and invalid final Bundle resource.

Expected:

~~~text
No changes were applied.
~~~

Verify authoritative state, endpoint allocation, revision, and runtime generation did not partially change.

## S-003 — Internet Access escape/bypass protection — MANDATORY

Exercise and retain results for:

- unapproved source;
- unapproved FQDN;
- wrong port;
- loopback;
- RFC1918/private target where unsafe;
- link-local;
- cloud metadata endpoint;
- IPv6 local/private where unsafe;
- IP-literal bypass;
- wildcard boundary bypass;
- DNS rebinding-style behavior;
- malformed CONNECT;
- CONNECT/SNI mismatch where applicable;
- unsafe ECH-dependent validation path where applicable;
- corrupt/missing current policy generation.

All unsafe paths must be denied/fail closed according to the current contract.

## S-004 — Secret leakage — MANDATORY

Inspect:

- normal show output;
- help/completion;
- audit;
- diagnostics;
- support bundle;
- ConfigurationBundle export;
- bootstrap/enrollment logs;
- server/agent logs used during E2E.

No raw ticket, OAuth secret, private key, transport token, credential, or unrestricted sensitive file content may be exposed outside its explicit one-time/secure contract.

## S-005 — CLI parser and shell safety — MANDATORY

Attempt command substitution, wildcard expansion, pipes, metacharacters, malformed quoting, and ambiguous selectors through the public CLI.

Verify the CLI treats them according to its parser contract and never unexpectedly executes a shell command.

## S-006 — Role boundary — MANDATORY

Repeat O-012 plus Server read-only visibility of Agent-owned Remote Services.

Verify Server inspection does not become unauthorized remote Agent mutation.

## S-007 — Server outage — MANDATORY

With healthy Remote Services:

- make Server temporarily unavailable;
- observe existing endpoints and Agent state;
- create/edit an Agent Remote Service from synchronized metadata;
- restore Server;
- verify sync and endpoint continuity.

No temporary outage may silently reassign an existing endpoint.

## S-008 — Agent or target outage — MANDATORY

Stop/disconnect Agent and separately stop the target service.

Verify HEALTHY -> DEGRADED transition, truthful reason, preserved reservation, and automatic recovery.

## S-009 — Runtime activation failure and rollback — MANDATORY

Inject a controlled runtime activation failure after validation in a disposable environment.

Expected:

- apply fails;
- previous authoritative configuration restored;
- previous runtime restored where rollback succeeds;
- incomplete rollback is reported truthfully;
- real previous traffic remains/restores according to contract.

Do not confuse valid-but-unreachable target DEGRADED state with an invalid activation that requires rollback.

## S-010 — Backup/restore negative cases — MANDATORY

Attempt restore using:

- truncated archive;
- corrupt database;
- unsupported newer schema;
- missing required trust material.

Expected: fail closed with explicit reason; no unsafe partially restored runtime.

## S-011 — Stale synchronized Agent catalog — MANDATORY

1. synchronize Agent metadata;
2. disconnect the Agent from the Server;
3. create/edit a valid local Remote Service using cached metadata;
4. while disconnected, change/delete the referenced authoritative Server Object;
5. reconnect.

Expected:

- synchronization revalidates the reference;
- invalid dependency remains visible as DEGRADED;
- runtime activation is not performed with a now-invalid dependency;
- endpoint identity already assigned is not silently rebound to another target;
- the reason identifies the invalid/missing dependency.

## S-012 — Offline Remote Service deletion — MANDATORY

Delete an existing Remote Service while Agent-to-Server connectivity is unavailable.

Verify:

- local desired configuration removes the service;
- Server may temporarily show prior known unavailable/DEGRADED state;
- the reservation is not reused for another service before delete synchronization is processed;
- reconnect synchronizes deletion and releases the endpoint;
- no extra operator action is required.

## S-013 — Endpoint-pool exhaustion and recovery — MANDATORY

Using disposable capacity, exhaust normal and Fixed TCP endpoint pools separately through public CLI operations.

Verify:

- pools never overlap or steal reservations;
- allocation failure is explicit when Server allocation is available;
- an offline-created valid service may remain DEGRADED/Pending allocation when capacity cannot be checked until reconnect;
- when capacity becomes available, pending allocation recovers according to contract;
- deletion returns capacity;
- concurrent allocations never receive duplicate endpoints.

## S-014 — Name, reserved-token, duplicate, and selector corner cases — MANDATORY

Through public CLI, test:

- duplicate public names that would be ambiguous;
- reserved tokens such as enabled, disabled, and policy in conflicting positions;
- missing Object/Group/Service/Permission references;
- invalid CIDR/IP/FQDN/port values;
- ambiguous selector;
- invalid Managed Host as Internet Access destination;
- destination Group containing a Managed Host;
- Remote Service destination resolving to multiple targets;
- duplicate effective Destination + Service on one Agent.

All invalid cases must fail atomically and produce actionable user-facing errors.

## S-015 — Network interruption during live traffic — MANDATORY

During real SSH/HTTP/HTTPS/Custom TCP/Fixed TCP traffic, separately inject:

- Agent-to-Server interruption;
- Relay Host-to-target interruption;
- target process restart;
- abrupt client disconnect;
- Server process restart where supported.

Verify truthful HEALTHY/DEGRADED transitions, stable endpoint identity, no cross-session data leakage, and automatic recovery where specified.

## S-016 — Authentication/credential corner cases — MANDATORY when applicable

Exercise CLI-configured AI/MCP and enrollment credentials with:

- valid;
- invalid;
- revoked;
- expired;
- repeated/replayed use where the protocol defines single use;
- concurrent double redemption for Zero-Touch;
- authentication still required while AI Access policy enforcement is disabled.

No expired/revoked credential may become valid because policy enforcement is disabled.

## S-017 — DNS, TLS, CA, and public-hostname failure cases — MANDATORY

Through supported CLI-generated Enrollment/Zero-Touch/Remote Service paths, exercise:

- DNS NXDOMAIN/unresolvable public hostname;
- hostname resolving to an unexpected address;
- certificate hostname mismatch;
- untrusted/incorrect CA;
- expired/not-yet-valid certificate where feasible in disposable test infrastructure;
- configured public hostname removed or changed;
- bootstrap hostname/public hostname disagreement where both concepts exist.

Expected:

- TLS verification is never silently disabled;
- enrollment/bootstrap failure is explicit and safe;
- a hostname failure does not silently rewrite persistent control identity;
- recovery after restoring correct DNS/TLS does not require unrelated state destruction.

## S-018 — ConfigurationBundle schema/patch corner cases — MANDATORY

Through `test configuration`, `system diff configuration`, and `system apply configuration`, exercise:

- omitted Resource -> unchanged;
- omitted field on existing Resource -> unchanged;
- explicitly supplied list -> exact desired list;
- `state: absent` -> explicit deletion/reset;
- `state: absent` combined with present-state fields -> reject;
- wrong `configurationBundle.context` -> reject before mutation;
- Server Bundle containing Agent-only Remote Services -> reject;
- Agent Bundle containing Server Objects/Policies -> reject;
- redaction placeholder such as REDACTED is not accepted as a new real secret;
- same desired state -> NO CHANGE.

## S-019 — Security-impact confirmation corner cases — MANDATORY

Use public CLI to perform changes that broaden or sharply restrict access.

Required cases include:

- deleting the last BLACKLIST blocking Rule;
- disabling policy enforcement;
- resetting a restrictive policy;
- deleting/removing a blocking condition;
- removing the last enabled WHITELIST allow Rule;
- rollback/restore to a state that broadens access.

Verify warning text describes the effective result before Apply and Cancel leaves authoritative state unchanged.

Rollback and restore must not bypass the same validation/security-impact/activation/verification pipeline used by normal Apply.

## S-020 — Boundary and capacity off-by-one cases — MANDATORY

For every user-visible bounded capacity available through CLI, exercise:

~~~text
0 or empty state where valid
1
maximum - 1
maximum
maximum + 1
~~~

At minimum apply this to:

- Zero-Touch batch issuance/active-unused capacity;
- endpoint-pool remaining capacity;
- bulk enrollment capacity where bounded;
- concurrency limits exposed by the current candidate.

Use the current authoritative limits at execution time. Do not hard-code stale historical limits into the harness.

## S-021 — Failure during mutation/activation — MANDATORY on disposable environment

Inject failure at representative phases while the operation is initiated only through public CLI:

- after validation but before authoritative commit;
- after candidate authoritative transaction but during runtime generation;
- during activation/verification;
- during automatic rollback.

Verify truthful error classification, no false SUCCESS, no unexplained partial state, and actionable `system diagnostics` recovery guidance when automatic rollback is incomplete.

## S-022 — Long-lived, half-close, abrupt-close, and idle connection cases — MANDATORY

For representative TCP services, exercise:

- long-lived connection;
- client FIN/normal close;
- abrupt RST/kill;
- one side stops sending while the other continues;
- idle period followed by resumed traffic where the service contract permits.

Verify cleanup, no endpoint leakage, no cross-session data leakage, and correct new-connection policy evaluation after the old session ends.

## S-023 — Bootstrap catalog false-HEALTHY prevention — MANDATORY

Use a clean Agent enrollment that declares an initial Remote Service whose local target is already reachable.

Before explicit relay/proxy runtime verification, inspect only through public CLI:

~~~text
show status
show remote-services
show remote-service <NAME>
~~~

Expected:

- allocated endpoint may be visible;
- local target reachability alone does not produce HEALTHY;
- status remains DEGRADED/runtime activation pending until actual relay verification succeeds;
- Server read-only Remote Service view must not contradict the Agent by reporting false HEALTHY.

Then complete real external traffic/relay verification and verify transition to HEALTHY on the same service identity and endpoint.

# 11. Parallel and simultaneous multi-host scenarios

Parallel multi-host execution is a mandatory part of FULL_USER_E2E, not only a performance optimization.

## C-001 — All applicable test hosts online simultaneously — MANDATORY

Bring every available supported-platform test host online at the same time.

Target matrix:

~~~text
Ubuntu 24
Windows 10
Rocky Linux 8
Rocky Linux 9
Amazon Linux 2023
macOS Apple Silicon
~~~

Each applicable host must simultaneously maintain:

- Managed Host identity;
- Agent connection;
- at least one Remote Service where the platform supports it;
- correct Server inventory;
- independent endpoint identity.

Required gate:

~~~text
ALL_TEST_HOSTS_SIMULTANEOUSLY_ONLINE=PASS
HOST_IDENTITY_CROSS_TALK=0
ENDPOINT_COLLISIONS=0
~~~

A missing environment is BLOCKED_ENVIRONMENT, not a synthetic PASS.

## C-002 — Parallel enrollment across all hosts — MANDATORY

Issue independent Zero-Touch/manual enrollment material as appropriate and enroll multiple platform hosts concurrently.

Verify:

- identities remain unique;
- each enrollment binds to the intended host;
- no ticket crosses hosts;
- capacity accounting is correct;
- concurrent same-ticket redemption is denied;
- all successful hosts appear correctly in Server inventory.

## C-003 — Parallel Remote Service creation and endpoint allocation — MANDATORY

On multiple Agent Hosts at the same time, create normal TCP and Fixed TCP Remote Services.

Verify:

- unique endpoint allocation;
- correct pool selection;
- no duplicate/overlapping reservation;
- no lost service registration;
- Server/Agent views converge;
- traffic reaches only the intended target.

## C-004 — Simultaneous real traffic on all hosts — MANDATORY

Generate real user traffic to every available host concurrently.

Include a mix of:

- SSH;
- HTTP;
- HTTPS;
- Custom TCP;
- Fixed TCP;
- Relay Host traffic.

Verify per-host correctness and aggregate correctness. One failing host cannot be hidden by aggregate throughput.

## C-005 — Parallel Internet Access from multiple protected sources — MANDATORY

Generate approved and denied outbound traffic concurrently from multiple protected sources/Managed Hosts.

Verify source-specific policy isolation, destination/port enforcement, and absence of cross-source policy leakage.

## C-006 — Parallel AI/MCP identities and calls — MANDATORY when feature included

Use multiple authenticated AI identities/sessions concurrently against different and overlapping target/permission scopes.

Verify:

- per-call authorization is evaluated independently;
- no cached ALLOW leaks into a later DENY;
- audit attribution remains correct;
- one identity cannot inherit another identity's session or permissions.

## C-007 — Policy mutation while all-host traffic is active — MANDATORY

While all-host traffic is active:

1. change Remote Access and/or Internet Access policy through Server CLI;
2. keep representative existing sessions alive;
3. start new sessions immediately before/after Apply.

Verify current contract for existing sessions and prove new connections use the new policy immediately without cross-host inconsistency.

## C-008 — Simultaneous Agent restart/reconnect storm — MANDATORY

Restart or disconnect multiple/all Agent Hosts together, then restore connectivity.

Measure:

- reconnect success;
- time to inventory convergence;
- endpoint preservation;
- pending allocation recovery;
- Server CPU/RSS/FD;
- no duplicate identities or endpoint reallocations.

## C-009 — Server outage with all Agents active — MANDATORY

With multiple Agents and real traffic active, interrupt Server availability.

On selected Agents, perform supported offline create/edit/delete operations through CLI. Restore Server and verify all Agents converge correctly, including stale-reference revalidation and deferred endpoint release/allocation.

## C-010 — Parallel ConfigurationBundle apply — MANDATORY

Apply independent Agent Bundles on multiple hosts concurrently while a Server Bundle is tested/applied through the Server CLI.

Verify context isolation:

~~~text
Server Bundle -> Server atomicity only
Agent Bundle  -> one Agent Host atomicity only
~~~

No implementation may pretend that the cross-host operation is one distributed atomic transaction.

## C-011 — Concurrent destructive/race cases — MANDATORY

Coordinate deliberate races:

- same Zero-Touch ticket redeemed twice;
- same endpoint-pool capacity contested by concurrent creates;
- same referenced Object deleted while another session tries to use it;
- same policy revision edited by two administrator sessions;
- service deletion synchronization racing with new allocation.

Expected outcome must be deterministic, fail safe, and leave no duplicate endpoint, orphaned resource, lost update, or authorization bypass.

## C-012 — All-host simultaneous reboot recovery — MANDATORY on disposable/approved hosts

Reboot all applicable Agent test hosts within the same test window.

After recovery, use CLI on every host plus Server CLI inventory to verify:

- autostart;
- identity continuity;
- endpoint continuity;
- policy continuity;
- real traffic;
- no host requires manual re-enrollment unless explicitly documented.

## C-013 — Parallel Agent update/restart convergence — MANDATORY on disposable/approved hosts

Update or restart multiple applicable Agent Hosts within the same maintenance window while the Server remains active.

Verify:

- each host preserves identity;
- endpoints remain mapped to the correct host/service;
- hosts reconnect independently;
- one failed host does not corrupt another host's state;
- Server inventory converges without duplicates;
- real traffic resumes per host.

## C-014 — Parallel mixed lifecycle operations — MANDATORY

Across different Agent Hosts at the same time perform a controlled mix of:

- create Remote Service;
- edit same-pool target/service;
- disable/enable;
- delete;
- synchronize;
- diagnostics;
- real user connection attempts.

Verify isolation between hosts and deterministic final state. A lifecycle operation on one host must not release, rename, or reassign another host's endpoint.

# 12. Performance test contract

Performance testing is part of FULL_USER_E2E.

The current product documents do not define universal numeric throughput/CPS/latency SLOs for every hardware/network combination. Therefore:

- always measure and retain metrics;
- always compare against a same-environment direct-path baseline when technically possible;
- apply numeric PASS thresholds only from an explicitly selected performance profile/SLO;
- if no numeric thresholds are defined, report PERFORMANCE_NUMERIC_QUALIFICATION=MEASURED_NOT_QUALIFIED rather than inventing a PASS threshold;
- functional/security failures under load are always FAIL regardless of numeric SLO.

Required performance evidence:

~~~text
PERF_PROFILE=
LOAD_GENERATOR_HW=
SERVER_HW=
AGENT_HW=
TARGET_HW=
NETWORK_RTT_DIRECT_MS=
NETWORK_RTT_RELAY_MS=
NIC_SPEED=
DURATION=
CONCURRENCY=
CPS_TARGET=
PAYLOAD_PROFILE=
THROUGHPUT_UP_MBIT_S=
THROUGHPUT_DOWN_MBIT_S=
THROUGHPUT_BIDIR_UP_MBIT_S=
THROUGHPUT_BIDIR_DOWN_MBIT_S=
CONNECT_P50_MS=
CONNECT_P95_MS=
CONNECT_P99_MS=
REQUEST_P50_MS=
REQUEST_P95_MS=
REQUEST_P99_MS=
ERROR_RATE=
RECONNECT_RATE=
SERVER_CPU_AVG_MAX=
SERVER_RSS_AVG_MAX=
SERVER_FD_AVG_MAX=
AGENT_CPU_AVG_MAX=
AGENT_RSS_AVG_MAX=
AGENT_FD_AVG_MAX=
DROPPED_CONNECTIONS=
DATA_INTEGRITY_ERRORS=
~~~

Default full-run durations unless the selected performance profile overrides them:

~~~text
WARMUP=60s
STEADY_STATE_EACH_CASE=300s
SOAK=3600s
~~~

Preferred test data profiles:

~~~text
small request/response
1 KiB
64 KiB
1 MiB
continuous stream
large file transfer
~~~

Use checksums for file-transfer integrity where applicable.

## P-001 — Direct-path baseline — MANDATORY

Measure the same target service without Data Relay Link, from the same load generator and network path where feasible.

Record throughput, connection latency, CPS, CPU, and error rate.

If a comparable direct path is impossible due to the isolated-network design, record BASELINE_UNAVAILABLE with the exact reason; do not fabricate a comparison.

## P-002 — Remote Access one-way throughput: User -> target — MANDATORY

Generate sustained upload/request traffic through a Remote Service public endpoint.

Measure:

- application goodput;
- server and Agent CPU/RSS;
- retransmission/error symptoms;
- data integrity.

Use SSH/SCP, HTTP upload, or an iperf3/custom TCP target through a DRLink TCP Remote Service as appropriate.

## P-003 — Remote Access one-way throughput: target -> User — MANDATORY

Generate sustained download/response traffic through the same public path.

Measure the same metrics independently from P-002.

## P-004 — Remote Access simultaneous full-duplex throughput — MANDATORY

Generate traffic in both directions at the same time.

A suitable TCP test service may use iperf3 bidirectional mode or an equivalent full-duplex harness published through a DRLink Remote Service.

Record independent upstream and downstream goodput plus aggregate resource usage.

## P-005 — Connection establishment rate / CPS — MANDATORY

Measure new successful connections per second through the public endpoint.

Ramp connection rate through the selected performance profile until the configured target or observed saturation/failure boundary.

Record:

- attempted CPS;
- successful CPS;
- failed/time-out connections;
- connect p50/p95/p99;
- Server/Agent CPU, memory, and FD usage;
- recovery after the load stops.

Do not convert a saturation point into a product defect unless it violates an approved performance profile or functional safety contract.

## P-006 — Concurrent active connections — MANDATORY

Hold increasing numbers of simultaneous established connections.

At minimum exercise several tiers including low, moderate, and high concurrency relative to the selected target profile.

Verify:

- no endpoint cross-talk;
- no data corruption;
- new policy evaluation still works for new connections;
- process remains responsive;
- diagnostics and show commands remain usable;
- cleanup returns resources.

## P-007 — Connect/request latency — MANDATORY

Measure TCP connect and application request latency through:

- direct Remote Service;
- Relay Host Remote Service;
- Fixed TCP Remote Service;
- HTTPS passthrough where applicable.

Record p50/p95/p99, not only averages.

## P-008 — Mixed-service workload — MANDATORY

Run simultaneous traffic across multiple service types, for example:

- SSH interactive/transfer;
- HTTP;
- HTTPS;
- Custom TCP;
- Fixed TCP.

Verify one hot service does not corrupt endpoint identity or policy behavior of another.

## P-009 — Multi-host scale — MANDATORY

Exercise the product operating range using Managed/Agent Host tiers:

~~~text
1
5
10
30
50
~~~

Where full physical/VM capacity for a tier is unavailable, use the maximum real-host tier available and record the missing tier as BLOCKED_ENVIRONMENT, not PASS.

At each tier measure:

- healthy Agent connectivity;
- inventory/show response time;
- Remote Service count;
- policy evaluation correctness;
- endpoint allocation;
- CPU/RSS/FD;
- reconnect storm behavior.

The goal is to validate the documented few-to-few-dozen operating model, not to claim unsupported fleet scale.

## P-010 — Internet Access throughput and bidirectional application data — MANDATORY

For an approved destination, measure:

- protected host -> Internet upload/request throughput;
- Internet -> protected host response/download throughput;
- simultaneous request/response where the application permits;
- HTTP/HTTPS CONNECT/application latency;
- policy lookup under load.

Repeat a deny test during load to prove security policy is not bypassed under performance pressure.

## P-011 — AI/MCP performance — MANDATORY when feature included

Measure representative allowed operations:

- host-info/process-read request rate and latency;
- file read/download throughput;
- file write/upload throughput if permitted;
- concurrent AI/MCP sessions;
- authentication/authorization latency;
- audit generation under load.

Also verify denied operations remain denied under concurrent load.

If the candidate excludes AI/MCP, record NOT_APPLICABLE with feature evidence.

## P-012 — Connection churn and reconnect storm — MANDATORY

Repeatedly connect/disconnect clients and Remote Service user sessions.

Include:

- external connection churn;
- Agent reconnect storm after temporary Server outage;
- target-service flap;
- enable/disable cycles.

Verify no endpoint reassignment, reservation leak, unbounded FD growth, or stuck DEGRADED state.

## P-013 — Soak / long-duration stability — MANDATORY

Run mixed representative traffic for the configured soak duration; default 3600 seconds.

Collect time-series CPU, RSS, FD, connection count, error count, endpoint state, and policy/audit health.

PASS of functional soak requires:

- no crash/restart loop;
- no unexplained endpoint change;
- no authorization bypass;
- no data-integrity error;
- no unbounded resource growth indicating a leak;
- normal recovery after load ends.

Numeric resource ceilings come from the selected performance profile.

## P-014 — Backup/restart/recovery under load — MANDATORY

With active but disposable workload:

- create backup under supported activity;
- restart/reboot components according to scenario;
- restore in the designated recovery test;
- resume load.

Verify no corrupted authoritative state and that post-recovery traffic/policy matches pre-recovery intent.

## P-015 — Aggregate all-host throughput and fairness — MANDATORY

With C-001/C-004 topology active, run simultaneous throughput from all available test hosts.

Record:

- per-host forward/reverse/full-duplex throughput;
- aggregate Server throughput;
- per-host and aggregate error rate;
- Server and Agent resource usage;
- latency distribution per host;
- fairness/starvation symptoms.

A high aggregate number does not pass if one host is starved, misrouted, or silently failing.

## P-016 — CPS while throughput and policy load are active — MANDATORY

Run new-connection CPS load while sustained throughput and representative policy checks are already active.

Verify:

- successful CPS;
- connect p50/p95/p99;
- throughput degradation;
- authorization correctness;
- diagnostics responsiveness;
- recovery after load.

## P-017 — Recovery-time performance — MANDATORY

Measure time to recover after:

- Agent restart;
- all-Agent reconnect storm;
- Server restart/outage;
- target-service flap;
- endpoint capacity becoming available.

Record time to:

~~~text
Agent connected
inventory converged
endpoint active
Remote Service HEALTHY
first successful user connection
~~~

## P-018 — Operational commands under load — MANDATORY

While representative traffic is active, run read-only CLI operations:

~~~text
show status
show managed-hosts
show remote-services
test remote-access ...
test internet-access ...
system diagnostics
system audit
~~~

Verify they remain responsive and do not alter traffic.

Run supported backup under activity through:

~~~text
system backup
~~~

and verify backup consistency according to the backup contract.

## P-019 — Extended endurance profiles — OPTIONAL unless explicitly selected

In addition to the mandatory 1-hour FULL_USER_E2E soak, support:

~~~text
EXTENDED_SOAK=8h
ENDURANCE_SOAK=24h
~~~

Use these for overnight/endurance qualification when requested. Results must remain distinct from the mandatory 1-hour soak so historical shorter evidence is not misrepresented as 8h/24h evidence.

## P-020 — Network impairment characterization — MANDATORY when test infrastructure supports controlled impairment

Characterize representative traffic under controlled:

- added latency;
- jitter;
- packet loss;
- bandwidth restriction;
- brief network partition.

Measure throughput, latency, error/reconnect rate, endpoint continuity, and recovery time.

This scenario characterizes resilience; do not invent a numeric PASS threshold when no approved network-impairment SLO exists. Security and state-integrity failures remain FAIL.

## P-021 — Saturation and post-saturation recovery — MANDATORY

Increase connection/concurrency/load until the selected profile target is reached or a practical saturation boundary is observed.

Verify:

- failure is bounded and explicit;
- no authorization bypass under saturation;
- no duplicate endpoint or state corruption;
- control CLI remains recoverable;
- resources return after load;
- service returns to normal without reinstall/re-enrollment.

## P-022 — Control-plane plus data-plane mixed pressure — MANDATORY

While all-host data-plane load is active, concurrently execute through public CLI:

- show/list inventory;
- policy test/explain;
- ConfigurationBundle test/diff;
- audit reads;
- support bundle on a designated host;
- backup on a disposable Server environment.

Measure command latency and verify read-only operations do not mutate state. Any mutating operation must still obey revision/security-impact/atomicity rules under load.

# 13. Platform matrix

For FULL_USER_E2E, test every platform currently claimed by the candidate at its actual qualification level.

Current release validation includes this matrix:

~~~text
Ubuntu 24
Windows 10
Rocky Linux 8
Rocky Linux 9
Amazon Linux 2023
macOS Apple Silicon
~~~

For each platform record one of:

~~~text
PASS_REAL
PASS_SYSTEM_SERVICE
PASS_CONTAINER_ONLY
NOT_APPLICABLE
BLOCKED_ENVIRONMENT
FAIL
~~~

Do not upgrade container/userspace evidence into Real E2E PASS.

Where a platform cannot host the Server role, execute its applicable Agent/client scenarios only.

At least one FULL_USER_E2E pass must also prove the entire available matrix concurrently via C-001 through C-012; per-platform serial PASS alone is insufficient for the all-host simultaneous gate.

## 13.1 Topology matrix

FULL_USER_E2E must qualify every topology currently claimed by the candidate. Record unsupported/unclaimed topology explicitly rather than silently skipping it.

At minimum classify:

~~~text
DIRECT_PUBLIC_IP=
PUBLIC_DNS_HOSTNAME=
ENTERPRISE_SINGLE_443=
NAT_DNAT_PRIVATE_SERVER=
RESTRICTED_OUTBOUND_AGENT_NETWORK=
RELAY_HOST_TO_LAN_TARGET=
~~~

Use:

~~~text
PASS_REAL
NOT_APPLICABLE_NOT_CLAIMED
BLOCKED_ENVIRONMENT
FAIL
~~~

Public DNS and hostname behavior must include U-009/A-018. Enterprise single-443 or NAT/DNAT becomes mandatory whenever the current candidate/release documentation claims it as supported. A historical PASS from another HEAD is not current-run evidence.

# 14. Complete CLI coverage list used by E2E

This section mirrors the public v2.4 CLI/AI Master. It is a coverage checklist, not a second grammar authority.

FULL_USER_E2E requires every applicable entry below to be executed through the public CLI at least once and linked to scenario evidence. Presence in this list alone does not count as coverage.

## 14.1 Server show

~~~text
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
~~~

## 14.2 Server set

~~~text
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
~~~

## 14.3 Server unset

~~~text
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
~~~

## 14.4 Server test

~~~text
test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
test configuration <FILE|->
~~~

## 14.5 Server system

~~~text
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
~~~

## 14.6 Agent Host

~~~text
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
system synchronize

test configuration <FILE|->

system export configuration <FILE>
system diff configuration <FILE|->
system apply configuration <FILE|->

system diagnostics
system support-bundle
system version
system uninstall
~~~

When an Agent help/diagnostic surface recommends system synchronize, the command must parse and be role-correct.

## 14.7 External user/application commands

These are not DRLink grammar, but FULL_USER_E2E must use real clients appropriate to the service:

~~~text
ssh / scp / sftp
curl
wget
git
apt
real HTTP/HTTPS client
real Custom TCP client
performance load generator
supported AI/MCP client when applicable
~~~

Use only the commands actually applicable to the target OS/application.

# 15. Conditional ChatGPT Plus Plugin / MCP relay integration lane

This lane applies when the requested E2E scope includes `datarelay-labs/datarelay-link-plugin` or when a release/acceptance claim includes the ChatGPT Plus Plugin/relay path.

It is intentionally reported separately because the Plugin repository is an optional experimental integration layer. Core DRLink must continue to operate without it.

All DRLink state setup remains CLI-only. Plugin transport/authentication is exercised only through its supported integration surface.

## X-001 — Exact cross-repository identity — CONDITIONAL

Record separately:

~~~text
DRLINK_CORE_HEAD=
DRLINK_PLUGIN_HEAD=
PLUGIN_PACKAGE_VERSION_OR_ID=
DRLINK_MCP_ENDPOINT=
RELAY_ENDPOINT=
~~~

Never reuse Plugin evidence from another Core HEAD or vice versa.

## X-002 — Plugin package and MCP declaration — CONDITIONAL

Verify the actual package declares the intended remote Streamable HTTP MCP endpoint and does not embed literal credentials.

Package/relay metadata must not invent tools or redefine DRLink authorization.

## X-003 — OAuth 2.1 / owner-consent flow — CONDITIONAL

Exercise the currently supported Plugin authentication path, including as applicable:

- protected-resource metadata;
- authorization-server metadata;
- Authorization Code;
- PKCE S256;
- DCR/public client behavior;
- owner approval;
- access token;
- refresh/reconnect;
- revoke/disconnect.

Verify public/non-loopback OAuth uses durable protected state according to the Plugin contract and never falls back to unsafe mock authentication.

## X-004 — MCP relay pass-through — CONDITIONAL

Exercise:

~~~text
initialize
tools/list
tools/call
JSON-RPC error path
Mcp-Session-Id continuity
Last-Event-ID where applicable
Accept / Content-Type protocol behavior
~~~

Verify the relay preserves upstream tool schemas/annotations/security metadata and does not invent, filter, or reinterpret tools.

## X-005 — DRLink remains final authorization source — CONDITIONAL

Configure AI Identity, Permission, destination, and AI Access only through `drlink`.

Through the Plugin/relay path verify per call:

- DRLink ALLOW succeeds;
- DRLink DENY remains denied;
- policy change affects the next call;
- relay does not cache an earlier ALLOW;
- one Plugin identity/binding cannot inherit another's authorization.

## X-006 — Relay failure and secret safety — CONDITIONAL

Verify:

- missing/invalid/unreachable upstream fails closed;
- health output contains no secrets;
- Authorization headers/tokens are redacted from logs;
- upstream URL binding does not become a generic open proxy;
- configured HTTPS upstream retains hostname/SNI/certificate verification;
- restart/recovery preserves only the state explicitly intended to persist.

## X-007 — Core vs Plugin acceptance separation — CONDITIONAL

Final report must distinguish:

~~~text
CORE_CLI_E2E=
DIRECT_MCP_E2E=
CHATGPT_PLUGIN_RELAY_E2E=
~~~

A passing direct MCP test cannot substitute for a Plugin path failure. A Plugin path PASS cannot substitute for unexecuted public `drlink` CLI scenarios.

## X-008 — OAuth concurrency, abuse limits, and durable state — CONDITIONAL

Exercise concurrent DCR/authorize/token activity within the Plugin's supported PoC limits.

Verify:

- pending authorization capacity is bounded;
- unexpired pending owner consent is not evicted merely to admit churn;
- per-source rate protection is effective;
- active refresh-bound clients are not removed by ordinary inactive cleanup;
- restart preserves only intended durable client/refresh/revocation state;
- public/non-loopback OAuth does not silently become ephemeral.

## X-009 — Plugin OAuth state backup/restore — CONDITIONAL

Use the Plugin repository's supported backup/restore workflow for OAuth state.

After restore/restart, verify expected reconnect/revoke semantics and that secrets remain protected by required file/parent permissions.

## X-010 — Real ChatGPT Plus Plugin acceptance — CONDITIONAL when environment is available

If the acceptance claim explicitly includes ChatGPT Plus rather than only protocol interoperability, test the actual ChatGPT Plus Plugin/App installation and tool-use surface.

This is an external-client validation analogous to using real SSH/curl clients; it does not relax the DRLink CLI-only control-plane rule.

Verify end to end:

~~~text
ChatGPT Plus
→ Plugin package
→ OAuth/connect
→ relay
→ DRLink Server MCP
→ DRLink AI Access
→ Managed Host
~~~

Record the exact ChatGPT/Plugin environment and date. If the real ChatGPT surface is unavailable, report BLOCKED_ENVIRONMENT for a ChatGPT-specific claim rather than substituting a generic MCP client and calling it PASS.

# 16. Evidence and result rules

Every scenario result must be one of:

~~~text
PASS
FAIL
BLOCKED_ENVIRONMENT
NOT_APPLICABLE
NOT_RUN_BY_SCOPE
~~~

Rules:

- PASS requires current-run evidence from the exact candidate build.
- BLOCKED_ENVIRONMENT is not PASS.
- NOT_APPLICABLE requires an explicit product/platform reason.
- NOT_RUN_BY_SCOPE is allowed only for an explicitly narrowed request.
- A FULL_USER_E2E aggregate PASS is invalid if any mandatory applicable scenario is FAIL, BLOCKED_ENVIRONMENT, or NOT_RUN.
- A numeric performance PASS is invalid when no approved numeric performance profile/SLO is defined; use MEASURED_NOT_QUALIFIED for the numeric qualification while still reporting functional load-test results.
- A release PASS additionally follows all exact-HEAD and double-pass requirements in docs/RELEASE_VALIDATION.md.

Per scenario retain:

~~~text
SCENARIO_ID=
ROLE=
HOST=
START_UTC=
END_UTC=
SOURCE_HEAD=
PRODUCT_VERSION=
COMMANDS_EXECUTED=
EXPECTED=
OBSERVED=
RESULT=
FAILURE_CLASS=
EVIDENCE_PATHS=
NOTES=
~~~

Performance scenarios additionally retain raw machine-readable metrics when possible.

The run must also produce explicit coverage inventories:

~~~text
SCENARIO_TOTAL=
SCENARIO_PASS=
SCENARIO_FAIL=
SCENARIO_BLOCKED=
SCENARIO_NOT_APPLICABLE=
PUBLIC_CLI_COMMANDS_TOTAL=
PUBLIC_CLI_COMMANDS_EXECUTED=
PUBLIC_CLI_COMMANDS_UNEXERCISED=
PUBLIC_CLI_SURFACES_TOTAL=
PUBLIC_CLI_SURFACES_EXECUTED=
CANONICAL_MASTER_SCENARIOS_TOTAL=
CANONICAL_MASTER_SCENARIOS_EXECUTED=
ALL_TEST_HOSTS_EXPECTED=
ALL_TEST_HOSTS_SIMULTANEOUSLY_ONLINE=
~~~

Any non-zero unexercised applicable public CLI command or canonical mandatory scenario prevents FULL_USER_E2E PASS.

# 17. Final FULL_USER_E2E report

A full run must end with a summary at least equivalent to:

~~~text
PHASE=FULL_USER_E2E
EXECUTOR=ChatGPT
FINAL_AUDITOR=ChatGPT
CURSOR_EXECUTED_USER_E2E=NO
FINAL_STATUS=PASS|PARTIAL|FAIL

SOURCE_HEAD=
PRODUCT_VERSION=
RELEASE_CHANNEL=
RELAY_ENGINE_VERSION=

USER_SCENARIOS=PASS|PARTIAL|FAIL
OPERATOR_SCENARIOS=PASS|PARTIAL|FAIL
ADMIN_SCENARIOS=PASS|PARTIAL|FAIL
SECURITY_NEGATIVE=PASS|PARTIAL|FAIL
PERFORMANCE_FUNCTIONAL=PASS|PARTIAL|FAIL
PERFORMANCE_NUMERIC_QUALIFICATION=PASS|FAIL|MEASURED_NOT_QUALIFIED
MULTI_PLATFORM=PASS|PARTIAL|FAIL
TOPOLOGY_MATRIX=PASS|PARTIAL|FAIL
ALL_TEST_HOSTS_SIMULTANEOUSLY_ONLINE=PASS|PARTIAL|FAIL
PARALLEL_MULTI_HOST=PASS|PARTIAL|FAIL
PUBLIC_CLI_COMMAND_COVERAGE=
PUBLIC_CLI_SURFACE_COVERAGE=
DRLINK_CONTROL_PLANE_CLI_ONLY=PASS|FAIL
AI_ASSISTED_CLI=PASS|PARTIAL|FAIL
CHATGPT_PLUGIN_INTEGRATION=PASS|PARTIAL|FAIL|NOT_APPLICABLE
CANONICAL_MASTER_SCENARIO_COVERAGE=
UNEXERCISED_PUBLIC_COMMANDS=

REMOTE_ACCESS_REAL_TRAFFIC=
INTERNET_ACCESS_REAL_TRAFFIC=
AI_MCP_REAL_TRAFFIC=
ZERO_TOUCH=
CONFIGURATION_BUNDLE=
BACKUP_RESTORE=
REBOOT_RECOVERY=
UPDATE_RECOVERY=
ENDPOINT_CONTINUITY=

THROUGHPUT_FORWARD=
THROUGHPUT_REVERSE=
THROUGHPUT_BIDIRECTIONAL=
CPS=
CONCURRENT_CONNECTIONS=
CONNECT_P95=
CONNECT_P99=
SOAK=
RESOURCE_STABILITY=

UNRESOLVED_P0=
UNRESOLVED_P1=
UNRESOLVED_P2=
BLOCKERS=
EVIDENCE_ROOT=
~~~

If FINAL_STATUS is not PASS, list the exact failing/blocking scenario IDs.

# 18. Maintenance rule

Whenever a public CLI command, supported platform, topology, Access Policy semantic, Remote Service lifecycle, Internet Access behavior, AI/MCP capability, enrollment workflow, backup/restore behavior, or release gate changes, this document must be reviewed in the same change.

The invariant for future User E2E requests is:

~~~text
USER_E2E_REQUEST
-> ChatGPT is the executor and final auditor; do not delegate User E2E execution to Cursor
-> read exact repository state
-> pin exact candidate HEAD/build
-> execute this document's FULL_USER_E2E profile unless explicitly scoped
-> use real public CLI and real traffic
-> exercise ALLOW and DENY
-> execute performance in every required direction
-> bring all applicable test hosts online simultaneously and execute parallel multi-host gates
-> exercise every applicable public CLI command and CLI surface
-> keep all DRLink control/configuration/lifecycle actions CLI-only
-> exercise AI one-shot, AI error-correction, AI ConfigurationBundle, Export->AI->Reapply, and cross-context split workflows
-> retain evidence
-> report every skipped/blocked scenario honestly
~~~

# Appendix A — v2.4 operator manual runbook

This appendix retains the v2.4 manual operator procedure that previously occupied this root document. Tests A1 through the end-of-run summary stay in force as concrete public-CLI steps. They do not narrow FULL_USER_E2E. An unqualified User E2E request still means the matrix in sections 1–18, executed and audited by ChatGPT.

# Data Relay Link v2.4.0 — Rick Manual E2E Runbook

```text
PHASE_AFTER=V2_4_0_DEVELOPMENT_COMPLETE_SCOPE_FREEZE_AND_RICK_MANUAL_E2E_READINESS
PURPOSE=Human operator usability + real traffic validation BEFORE Final Qualification
OPERATOR=Rick
PUBLIC_TOOLS_ONLY=drlink, ?, help, menu, Tab, show, normal OS tools
FORBIDDEN=source inspection for syntax, SQLite edits, runtime JSON edits, private APIs, hidden helpers
```

## Candidate freeze identity

Fill these before starting:

| Field | Value |
|------|--------|
| Branch | `feature/v2.4.0-final-product-closure` |
| Exact HEAD | `<paste git rev-parse HEAD>` |
| Worktree clean | YES / NO |
| Install source | this exact HEAD (clean server install) |

```bash
git rev-parse HEAD
git status --short --branch
```

Do **not** change product code during the run unless a P0 security issue or hard blocker stops most remaining tests.

## Finding format (mandatory)

```text
FINDING_ID=RICK-XXX
AREA=
SEVERITY=P0|P1|P2|UX
HOST=
COMMAND_OR_ACTION=
EXPECTED=
ACTUAL=
REPRODUCIBLE=YES|NO
EVIDENCE=
```

Never paste Zero-Touch secrets, OAuth tokens, TLS private keys, or ACME account keys into findings.

## Blind UX checklist (record throughout)

For each section, note:

```text
Could syntax be discovered without source?
Was terminology understandable?
Did an error explain the next action?
Did menu/help/Tab agree?
Did any operation require hidden knowledge?
```

Target: `MANUAL_CLI_DEAD_ENDS=0`

## Canonical menu (server)

```text
menu
1) Managed Hosts
2) Objects
3) Remote Access
4) Internet Access
5) AI Access
6) System
```

Discoverability tips:

```text
?
help
help managed-hosts | objects | remote-access | internet-access | ai-access | system | workflows | commands
<command> ?
Tab
```

ConfigurationBundle / MCP TLS live under **System** help and `system ?` / `show ?` / `set ?` — not as separate top-level menu domains.

---

## Public MCP prerequisites (do before Section I)

Current lab server is the SSH alias `frp-e2e-server`. Do not commit the live public IP.

```text
PUBLIC_IP=<server public IPv4; do not commit>
SSH_ALIAS=frp-e2e-server
```

Rick must prepare a **project-controlled hostname** for real public MCP TLS:

```text
PUBLIC_MCP_REQUIRED_HOSTNAME=<choose, e.g. mcp.<your-domain>>
PUBLIC_MCP_REQUIRED_DNS=A/AAAA -> current server public IP
PUBLIC_MCP_REQUIRED_PORTS=TCP/80 (HTTP-01), TCP/443 (HTTPS /mcp)
```

Notes from readiness probe:

```text
fw.xdr.ooo        -> retired historical lab address (NOT this server; do not reuse blindly)
mcp.xdr.ooo       -> docs/CDN CNAME today; NOT usable as MCP endpoint without DNS change
TCP/80 on server  -> must be free/open for AUTO_ACME HTTP-01
TCP/443           -> currently used by frps on the installed lab host; plan coexistence / DNAT carefully
```

Do not change external DNS unless authorized. Record exact hostname chosen before Section I.

---

## Host availability worksheet

Fill at start of run:

| Host alias | Role | Reachable | Product installed | Safe disposable target | Notes |
|------------|------|-----------|-------------------|------------------------|-------|
| frp-e2e-server | Ubuntu 24 server | | | | |
| frp-e2e-linux114 | Ubuntu 24 client | | | | |
| frp-e2e-rocky8 | Rocky 8 client | | | | |
| frp-e2e-rocky9-rescue | Rocky 9 | | | | rescue host; keep independent of product uninstall |
| frp-e2e-aws | Amazon Linux 2023 client | | | | |
| frp-e2e-macos | macOS Apple Silicon client | | | | |
| frp-e2e-windows | Windows 10 client | | | | |
| frp-e2e-client | Linux client | | | | may be flaky |

Unavailable hosts: mark `SKIPPED_HOST_UNAVAILABLE` — do not invent PASS.

---

# SECTION A — Clean server install

### TEST A1 — Clean install

```text
TEST ID=A1
Objective=Clean install of exact candidate HEAD on disposable server
Precondition=Server has no prior DRLink state OR prior state purged per docs
Exact public command / operator action=
  Install using the documented server installer for this HEAD
  (example shape; use the actual documented path for this branch):
  curl -fsSL <immutable-installer-for-this-HEAD> | sudo bash
Expected result=Install completes; services start; branding is Data Relay Link
PASS/FAIL=
Finding=
```

### TEST A2 — Service status + launch

```text
TEST ID=A2
Objective=Services healthy; public CLI launches
Exact public command / operator action=
  systemctl status drlink-server --no-pager
  sudo drlink
Expected result=No traceback; prompt is Data Relay Link; no legacy FRP product UX
PASS/FAIL=
Finding=
```

### TEST A3 — Discovery surfaces

```text
TEST ID=A3
Objective=?, help, menu, version, doctor work
Exact public command / operator action=
  ?
  help
  menu
  system version
  system diagnostics
Expected result=
  Canonical roots only (show/set/unset/test/system/menu/help/exit)
  Menu matches Managed Hosts/Objects/Remote Access/Internet Access/AI Access/System
  No help legacy advertisement
  No traceback
PASS/FAIL=
Finding=
```

---

# SECTION B — Zero-Touch

Prefer discovery via `menu → Managed Hosts → Connect a Managed Host` or `set enrollment zero-touch`.

### TEST B1 — Issue one ticket (default TTL)

```text
TEST ID=B1
Objective=Issue one Zero-Touch ticket; default TTL; one-time secret display
Exact public command / operator action=
  set enrollment zero-touch
  (or menu → Managed Hosts → Connect a Managed Host)
Expected result=
  Ticket/command shown once with secret material
  Default TTL accepted without inventing syntax from source
PASS/FAIL=
Finding=
```

### TEST B2 — Secret not re-shown

```text
TEST ID=B2
Objective=Subsequent show does not reveal secret
Exact public command / operator action=
  show enrollments
  show managed-hosts
Expected result=No full secret/ticket reuse material displayed
PASS/FAIL=
Finding=
```

### TEST B3 — Redeem on real client

```text
TEST ID=B3
Objective=Real client redeems ticket
Precondition=Disposable Linux client host available
Exact public command / operator action=
  Run the one-line install/redeem command exactly as shown (once)
Expected result=
  Client created
  Managed Host created
  Ticket consumed
PASS/FAIL=
Finding=
```

### TEST B4 — Ticket reuse rejected

```text
TEST ID=B4
Objective=Consumed ticket cannot be reused
Exact public command / operator action=
  Re-run the same redeem command on another host or same host
Expected result=Rejected; no second client from same ticket
PASS/FAIL=
Finding=
```

### TEST B5 — Active-unused limit / revoke / capacity

```text
TEST ID=B5
Objective=Bounded active-unused tickets; revoke restores capacity
Exact public command / operator action=
  Issue multiple tickets until active-unused limit (help says max 10)
  unset enrollment <ID>   (or guided revoke)
  Issue again after revoke
Expected result=
  Limit enforced with actionable error
  Revoke unused restores capacity
  No database inspection required
PASS/FAIL=
Finding=
```

---

# SECTION C — Client lifecycle

Run on each available OS. Skip unavailable hosts explicitly.

### TEST C1 — Lifecycle controls

```text
TEST ID=C1-<OS>
Objective=status/pause/resume/restart/autostart where applicable
Host=
Exact public command / operator action=
  (on client) show status
  system pause
  system resume
  system restart
  system autostart
  system autostart disable   # if applicable
  system autostart enable    # if applicable
Expected result=Each command succeeds or explains OS limitation; identity unchanged
PASS/FAIL=
Finding=
```

### TEST C2 — Uninstall / reinstall identity

```text
TEST ID=C2-<OS>
Objective=Uninstall/reinstall semantics without surprise re-enrollment
Exact public command / operator action=
  system uninstall
  reinstall via documented path
  show status / server show client <ID>
Expected result=Documented identity/port semantics hold; record what survives
PASS/FAIL=
Finding=
```

---

# SECTION D — Remote Access (real traffic)

### TEST D1 — Publish services

```text
TEST ID=D1
Objective=Publish SSH/HTTP/HTTPS/Custom TCP as available
Exact public command / operator action=
  help workflows
  set published-service <NAME>
  show published-services
Expected result=Services listed with ports; discoverable without source
PASS/FAIL=
Finding=
```

### TEST D2 — SELF / ROUTED traffic

```text
TEST ID=D2
Objective=Real external traffic for SELF and ROUTED where configured
Exact public command / operator action=
  ssh -p <port> user@<public_hostname_or_ip>
  curl -v http://...
  curl -vk https://...
  appropriate TCP probe for custom service
Expected result=Traffic succeeds only when policy allows
PASS/FAIL=
Finding=
```

### TEST D3 — ALLOW → DENY mutation

```text
TEST ID=D3
Objective=Policy mutation affects new connections
Exact public command / operator action=
  set remote-access <RULE> ... action allow
  verify connect ALLOW
  set remote-access <RULE> ... action deny   # or equivalent unset/edit
  verify new connect DENY
Expected result=
  New connection reflects policy
  Completed prior session semantics unchanged (document observed behavior)
PASS/FAIL=
Finding=
```

---

# SECTION E — Objects / Groups

### TEST E1 — Network Object CRUD

```text
TEST ID=E1
Objective=IP/CIDR/FQDN Network Objects create/show/edit/delete protection
Exact public command / operator action=
  set network-object <NAME>
  show network-objects
  show network-object <NAME>
  show network-object <NAME> references
  unset network-object <NAME>
Expected result=No silent cascade; in-use delete protected with clear error; Managed Hosts remain lifecycle-managed through Managed Host commands
PASS/FAIL=
Finding=
```

### TEST E2 — Network Group

```text
TEST ID=E2
Objective=Flat membership, context validation, and reference protection
Exact public command / operator action=
  set network-group <NAME>
  show network-groups
  show network-group <NAME>
  show network-group <NAME> references
  unset network-group <NAME>
Expected result=Membership visible; invalid context rejected as a whole; delete protection when referenced
PASS/FAIL=
Finding=
```

---

# SECTION F — Internet Access (real apps)

Do **not** widen policy just to make apps pass.

### TEST F1 — Approved FQDN:port ALLOW

```text
TEST ID=F1
Objective=Approved destination allows curl/wget/git/apt as environment permits
Exact public command / operator action=
  set network-object ... / set service-object ... / set internet-access <RULE> mode whitelist source <SRC> destination <DST> service <SVC> enabled
  From authorized client source: curl/wget/git/apt to approved FQDN:port
Expected result=ALLOW only for approved destination+port+source
PASS/FAIL=
Finding=
```

### TEST F2 — DENY matrix

```text
TEST ID=F2
Objective=Unapproved dest / wrong port / wrong source / IP literal / private-metadata DENY
Exact public command / operator action=
  Attempt each deny class with real traffic or test internet-access
Expected result=Each class DENY; error/audit understandable
PASS/FAIL=
Finding=
```

---

# SECTION G — Fixed TCP

### TEST G1 — Lifecycle

```text
TEST ID=G1
Objective=create disabled-by-default → enable → authorize → deny → disable → delete
Exact public command / operator action=
  set fixed-tcp <NAME> ...
  show fixed-tcp
  set fixed-tcp <NAME> enabled
  probe from authorized source
  probe from unauthorized source
  unset fixed-tcp <NAME> enabled
  unset fixed-tcp <NAME>
Expected result=Disabled by default; probes match policy; delete clean
PASS/FAIL=
Finding=
```

---

# SECTION H — ConfigurationBundle (critical UX)

### TEST H1 — Export / test / diff / apply

```text
TEST ID=H1
Objective=Full Bundle loop including stdin paste
Exact public command / operator action=
  system export configuration /tmp/drlink-rick.yaml
  test configuration /tmp/drlink-rick.yaml
  system diff configuration /tmp/drlink-rick.yaml
  system apply configuration /tmp/drlink-rick.yaml
  system apply configuration -     # paste multi-resource Bundle via stdin
Expected result=
  Valid multi-resource Bundle works
  Confirmation defaults to No until confirmed
  No secrets in export
PASS/FAIL=
Finding=
```

### TEST H2 — NO CHANGE reapply / absent / omitted / broaden / secrets

```text
TEST ID=H2
Objective=Semantics: NO CHANGE, state:absent, omitted unchanged, broaden confirm, secret reject
Exact public command / operator action=
  Re-apply identical Bundle
  Apply Bundle with state: absent for one disposable resource
  Apply Bundle omitting an existing resource
  Apply access-broadening change (expect confirm)
  Attempt Bundle containing a secret field
Expected result=
  NO CHANGE reapply is clean
  absent removes only targeted resource
  omitted resource unchanged
  broadening requires confirmation
  secrets rejected
PASS/FAIL=
Finding=
```

---

# SECTION I — MCP Public TLS (mandatory external)

### TEST I1 — Configure + issue

```text
TEST ID=I1
Objective=AUTO_ACME public certificate issuance
Precondition=DNS A/AAAA + TCP/80 + TCP/443 ready for PUBLIC_MCP_REQUIRED_HOSTNAME
Exact public command / operator action=
  set mcp-tls hostname <PUBLIC_MCP_REQUIRED_HOSTNAME>
  set mcp-tls mode auto-acme
  set mcp-tls contact-email <ops-email>
  system certificate preflight
  system certificate issue
  show mcp-tls
  system diagnostics
  system diagnostics mcp
Expected result=Issue succeeds; show mcp-tls healthy; doctor clean for TLS
PASS/FAIL=
Finding=
```

### TEST I2 — External trust verification

```text
TEST ID=I2
Objective=Publicly trusted cert; hostname match; /mcp and OAuth metadata reachable
Exact public command / operator action=
  curl -vI https://<hostname>/mcp
  curl -fsS https://<hostname>/.well-known/oauth-authorization-server | head
  openssl s_client -connect <hostname>:443 -servername <hostname> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
Expected result=
  REAL_PUBLIC_TLS=PASS
  REAL_PUBLIC_ACME=PASS
PASS/FAIL=
Finding=
```

---

# SECTION J — Claude Remote MCP

UI labels may vary. High-level sequence only:

```text
Add Custom Connector
→ URL https://<hostname>/mcp
→ OAuth authorize
→ tools discovered
```

### TEST J1 — Connect + read tools

```text
TEST ID=J1
Objective=Claude connector OAuth + tool discovery
Exact public command / operator action=
  Complete Claude custom connector flow against https://<hostname>/mcp
  Invoke: list_hosts, get_host, get_system_info
Expected result=CLAUDE_REMOTE_CONNECTOR=PASS OR exact platform error recorded
PASS/FAIL=
Finding=
```

### TEST J2 — Controlled allow/deny

```text
TEST ID=J2
Objective=Policy ALLOW safe tools; DENY unauthorized
Exact public command / operator action=
  Configure AI Access for a disposable principal/host
  ALLOW: safe exec, safe read_file, safe write_file (disposable path)
  DENY: unauthorized host, unauthorized tool, read-only principal exec
  Confirm DRLink audit attribution (system audit / show ai-activity)
Expected result=Allow/deny match policy; audit names principal
PASS/FAIL=
Finding=
```

If Claude platform blocks: record exact platform error. Do **not** modify DRLink until a product-side defect is proven.

---

# SECTION K — ChatGPT Remote MCP

### TEST K1 — ChatGPT connector

```text
TEST ID=K1
Objective=ChatGPT remote MCP as account/plan allows
Exact public command / operator action=
  Connect same https://<hostname>/mcp
  OAuth + tool scan
  list_hosts / get_system_info
  AI Access DENY case
  If plan allows writes: safe exec / write_file
Expected result=Classify exactly one of:
  PASS
  READ_ONLY_PASS_WRITE_BLOCKED_PLATFORM
  BLOCKED_EXTERNAL_PLAN
  FAIL_PRODUCT
PASS/FAIL=
Finding=
```

Plan restrictions are **not** DRLink defects.

---

# SECTION L — MCP security

### TEST L1 — Principal/tool/host denies + policy flip

```text
TEST ID=L1
Objective=unknown principal / read-only / wrong host / denied tool / ALLOW→DENY next call
Exact public command / operator action=
  Exercise each case via connector or test ai-access
  Flip ALLOW→DENY; confirm next invocation denied
  Check audit attribution
Expected result=Fail closed; audit correct; no token leakage in UI/logs pasted to notes
PASS/FAIL=
Finding=
```

---

# SECTION M — Backup / Restore

Use disposable state only.

### TEST M1 — Backup mutate restore

```text
TEST ID=M1
Objective=Backup → mutate/delete disposable state → restore → verify
Exact public command / operator action=
  system backup
  Change/delete disposable Objects/policies/Remote Services/MCP TLS non-secret state/Zero-Touch non-secret lifecycle state
  system restore <PATH>
  system diagnostics
  Functional spot-check
Expected result=Restored state matches backup; secrets never displayed; doctor clean
PASS/FAIL=
Finding=
```

---

# SECTION N — Upgrade / Reboot

### TEST N1 — Reboot persistence

```text
TEST ID=N1
Objective=Server/client reboot persistence
Exact public command / operator action=
  reboot server; reboot client
  verify autostart, identity, Remote Services, policies, MCP TLS, ACME timer
Expected result=No unexpected re-enrollment; MCP TLS persists; timer active if AUTO_ACME
PASS/FAIL=
Finding=
```

### TEST N2 — Update workflow

```text
TEST ID=N2
Objective=Documented update preserves identity
Exact public command / operator action=
  system update product   # and/or documented reinstall update path per OS
Expected result=Identity/ports preserved; no surprise re-enrollment
PASS/FAIL=
Finding=
```

---

# SECTION O — Uninstall / Reinstall

### TEST O1 — Preserve vs purge

```text
TEST ID=O1
Objective=Documented uninstall preserving state vs purge
Exact public command / operator action=
  Follow documented uninstall paths
  Explicitly record what survives vs removed
  Reinstall
Expected result=Matches docs; no inference
PASS/FAIL=
Finding=
```

---

# SECTION P — Doctor / Support Bundle

### TEST P1 — Sanitized diagnostics

```text
TEST ID=P1
Objective=doctor + support bundle useful and sanitized
Exact public command / operator action=
  system diagnostics
  system support-bundle
  Inspect bundle metadata only (do not exfiltrate)
Expected result=
  Useful diagnostics
  No raw Zero-Touch ticket
  No OAuth token
  No TLS private key
  No ACME account key
  No sensitive file content
PASS/FAIL=
Finding=
```

---

# SECTION Q — Blind UX rollup

```text
TEST ID=Q1
Objective=Roll up discoverability across the run
Exact public command / operator action=Review notes from A–P
Expected result=MANUAL_CLI_DEAD_ENDS=0
PASS/FAIL=
Finding=
```

---

## End-of-run summary template

```text
RICK_MANUAL_E2E_STATUS=PASS|PARTIAL|FAIL|BLOCKED
CANDIDATE_HEAD=
REAL_PUBLIC_TLS=
REAL_PUBLIC_ACME=
CLAUDE_REMOTE_CONNECTOR=
CHATGPT_REMOTE_CONNECTOR=
MANUAL_CLI_DEAD_ENDS=
P0_COUNT=
P1_COUNT=
P2_COUNT=
UX_COUNT=
HOSTS_SKIPPED=
NEXT=consolidate findings → fix batch (except immediate P0/hard blockers)
```
