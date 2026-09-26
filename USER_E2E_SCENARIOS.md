# Data Relay Link — Full User E2E Execution Contract

> **Document role:** Canonical real-product E2E execution contract
> **Canonical path:** repository-root USER_E2E_SCENARIOS.md
> **Product:** Data Relay Link
> **Target:** v2.4 and later until superseded
> **Primary management interface:** drlink CLI
> **CLI/AI grammar authority:** docs/DATA_RELAY_LINK_CLI_AI_MASTER_v2.4_FINAL.md
> **Release validation:** docs/RELEASE_VALIDATION.md
> **Release checklist:** docs/RELEASE_CHECKLIST.md
> **Status:** Normative living document

## 1. Purpose

FULL_USER_E2E answers one question:

> Can real Users, Operators, and Administrators install, configure, use, break, recover, update, and remove Data Relay Link through the public product interfaces, with understandable behavior and acceptable real traffic performance?

This is not a read-only validation exercise and it is not a collection of unit, synthetic, or configuration checks.

The run must use real designated test servers and clients. During the run it is expected that test systems, services, policies, sessions, endpoints, and product state will be changed, interrupted, removed, reinstalled, rebooted, exhausted, corrupted in controlled ways, or made temporarily unusable.

The run exists to find:

- product defects;
- functions that do not work in real use;
- installation, enrollment, upgrade, uninstall, or recovery failures;
- CLI dead ends and undiscoverable syntax;
- confusing terminology or unclear workflow;
- ambiguous behavior;
- missing diagnostics or poor error messages;
- unsafe or surprising defaults;
- differences between direct CLI use and AI-assisted use;
- performance, concurrency, recovery, and data-integrity problems;
- documentation gaps;
- improvement opportunities that a real User, Operator, or Administrator would encounter.

When the user asks for User E2E, Full User E2E, 전체 E2E, 사용자 E2E, or equivalent without narrowing scope:

~~~text
PROFILE=FULL_USER_E2E
EXECUTOR=ChatGPT
FINAL_AUDITOR=ChatGPT
REAL_INSTALLS=YES
REAL_STATE_MUTATION=YES
DESTRUCTIVE_LIFECYCLE_TESTS=YES
REAL_EXTERNAL_TRAFFIC=YES
CLI_FIRST_PASS=YES
AI_ASSISTED_SECOND_PASS=YES
BIDIRECTIONAL_PERFORMANCE_THIRD_PASS=YES
PARALLEL_EXECUTION=YES_WHERE_INDEPENDENT
FIX_DURING_RUN=NO
CONSOLIDATE_FINDINGS_AFTER_RUN=YES
~~~

A targeted request may run a subset only when the user explicitly narrows the scope.

## 2. Non-negotiable execution rules

### 2.1 Real systems, real state changes

FULL_USER_E2E must operate designated test infrastructure as real customers would.

The following are normal and required when applicable:

- clean Server install;
- clean Agent install;
- Zero-Touch, manual, and bulk enrollment;
- real resource create/edit/delete;
- policy ALLOW and DENY changes;
- real Remote Service creation and removal;
- server and Agent restart/reboot;
- target-service stop/start;
- network interruption;
- Server outage;
- Agent outage;
- endpoint-pool exhaustion;
- ConfigurationBundle apply and removal;
- rollback;
- backup and restore;
- product update and Relay Engine update;
- uninstall and reinstall;
- stale state and concurrent writer tests;
- malformed/invalid input;
- performance saturation;
- simultaneous multi-host load.

A test server or client may become unusable as a result of a scenario. That is acceptable on designated test infrastructure and is itself evidence.

Do not weaken, skip, or replace a destructive scenario merely to keep a test machine healthy.

### 2.2 No mid-run product fixes

The E2E run and the product-fix loop are separate phases.

During FULL_USER_E2E:

~~~text
FIND_PROBLEM
-> record evidence
-> classify impact
-> mark current scenario FAIL or BLOCKED_BY_PRIOR_FAILURE as appropriate
-> continue every independent scenario that can still execute
-> do not patch product code
-> do not change implementation to make the test pass
-> do not hand a fix to Cursor yet
~~~

This rule applies even to P0/P1 defects and hard blockers.

If one defect prevents a dependent group of scenarios, record the dependency once, mark those scenarios BLOCKED_BY_PRIOR_FAILURE, and continue all unrelated lanes, platforms, roles, offline cases, failure cases, and exploratory product paths that remain executable.

Only after the planned run has been exhausted:

~~~text
END_OF_RUN
-> consolidate findings
-> de-duplicate root causes
-> rank P0/P1/P2/UX/DOC/PERF
-> update engineering Work Packet / issues
-> hand implementation fixes to Cursor when required
-> independently verify fixes
-> rerun affected scenarios
-> rerun full qualification when release policy requires it
~~~

The only reason to stop a specific scenario early is that continuing it would leave the designated test scope or create an external safety/security risk. That is recorded as a test result, not repaired during the run.

### 2.3 Public product path only

All DRLink management, configuration, lifecycle, diagnostics, recovery, and inspection actions used for E2E qualification must use the public drlink CLI.

Do not use the following to create, repair, or manufacture a PASS:

- direct SQLite or database mutation;
- direct runtime JSON/state mutation;
- private Python/module entry points;
- internal FRP helper CLIs;
- private management REST APIs;
- hidden compatibility commands when a canonical command exists;
- direct edits of generated runtime configuration;
- source inspection to discover syntax during the blind usability portion of a scenario.

Normal OS and application tools are required for real data-plane behavior, including ssh, scp, sftp, curl, wget, git, apt, openssl, application clients, TCP load tools, and supported AI/MCP clients.

### 2.4 Exact candidate evidence

A release-qualifying result must come from the exact candidate build under test.

Record both source identity and installed product identity. Historical results, a different Git HEAD, container-only evidence, synthetic tests, Cursor output, or another lab installation are not qualifying evidence for the current candidate.

Historical or cross-HEAD environments may still be exercised to discover additional defects, but they must be labeled NON_QUALIFYING_EXPLORATORY.

### 2.5 ChatGPT owns User E2E

~~~text
USER_E2E_EXECUTOR=ChatGPT
USER_E2E_FINAL_AUDITOR=ChatGPT
CURSOR_MAY_EXECUTE_FULL_USER_E2E=NO
CURSOR_MAY_DECLARE_USER_E2E_PASS=NO
~~~

Cursor may implement fixes only after the run is consolidated and the engineering workflow moves into the fix phase.

## 3. Three-pass test model

Every applicable product workflow is tested in three passes.

### PASS 1 — Direct CLI operation

ChatGPT acts directly as User, Operator, and Administrator.

Goals:

- install the real product;
- discover commands from the CLI and product documentation;
- perform the workflow through drlink;
- use real external clients for traffic;
- verify state before, during, and after mutation;
- find confusing or ambiguous UX;
- verify error recovery without source knowledge;
- exercise shell one-shot, REPL, menu, Wizard, help, ?, Tab, file Bundle, and stdin Bundle;
- execute every applicable public command family at least once.

This is the primary functional truth.

### PASS 2 — AI-assisted operation

Repeat the applicable workflow using AI assistance as the user-facing input layer.

AI must translate real user intent into one or both of:

~~~text
natural-language intent
-> drlink command(s)
-> operator executes through public drlink CLI
~~~

and:

~~~text
natural-language intent
-> ConfigurationBundle
-> test
-> diff
-> apply
-> show/verify
-> rollback/recovery when applicable
~~~

PASS 2 is not satisfied by explaining what the user could type. The generated command or Bundle must actually be executed against the test environment.

Verify:

- correct role/context is chosen;
- canonical command grammar is produced;
- generated commands are safe to paste;
- shell metacharacters or quoting do not create a bypass;
- missing information is requested clearly;
- invalid AI output can be corrected from CLI feedback;
- multi-resource requests become coherent Bundles;
- AI does not bypass drlink by mutating private state;
- AI and direct CLI produce equivalent intended state;
- ambiguity, overlong commands, hidden assumptions, or confusing guidance are recorded as findings.

When AI/MCP or the ChatGPT Plugin is itself a product feature in acceptance scope, also execute the actual connector/auth/tool path. That integration lane is separate from AI-assisted CLI generation and may not substitute for it.

### PASS 3 — Bidirectional performance and resilience

After functionality exists, exercise the real data path in both directions.

Mandatory directions:

~~~text
FORWARD=external/protected user -> target
REVERSE=target/Internet response -> user
FULL_DUPLEX=both directions simultaneously
~~~

Measure direct-path baseline where feasible and then the DRLink path.

Performance testing must include throughput, connection establishment, concurrency, latency, mixed workload, resource use, error rate, recovery, saturation, and soak. Security and policy correctness must remain enforced under load.

## 4. Roles

| Role | Real operating perspective | Required work |
| --- | --- | --- |
| User | Consumes published Remote Access, Internet Access, or AI capability | Connect, authenticate, transfer data, use applications, observe ALLOW/DENY, survive policy/restart changes |
| Operator | Runs Agent Hosts and Remote Services | Install/enroll Agent, create/edit/delete Remote Services, pause/resume/restart, synchronize, diagnose, update, uninstall/reinstall |
| Administrator | Runs Server and security/control state | Install Server, Managed Hosts, Objects/Groups, policies, AI identities/permissions, audit, revision, Bundle, backup/restore, update, certificates, uninstall/reinstall |
| External load generator | Generates real traffic | forward/reverse/full-duplex throughput, CPS, concurrency, latency, churn, soak |
| Target service | Real destination behind Direct or Relay Agent | SSH/HTTP/HTTPS/Custom TCP/Fixed TCP/application behavior |

A single human or ChatGPT session may perform several roles, but every evidence record identifies the active role and host.

## 5. Product lifecycle that must be exercised

FULL_USER_E2E follows the actual product lifecycle instead of treating features as isolated commands.

### L0 — Environment and clean installation

- verify test host identity, OS, architecture, network, DNS, and topology;
- clean Server install from the exact candidate;
- first launch and public CLI discovery;
- clean Agent installs on every applicable platform;
- verify public hostname/IP bootstrap behavior;
- verify TLS/certificate prerequisites when applicable.

### L1 — Enrollment and identity

- Zero-Touch issue, redeem, one-time secret behavior, expiry, revoke, reuse rejection, capacity;
- manual enrollment;
- bulk enrollment;
- Managed Host identity and address inventory;
- reconnect and identity persistence.

### L2 — Configuration construction

- Network Objects and Groups;
- Service Objects and Groups;
- AI Identity;
- Permission Objects and Groups;
- Remote Access rules;
- Internet Access rules;
- AI Access rules;
- endpoint/pool behavior;
- file and stdin ConfigurationBundle;
- Wizard create/edit/cancel/invalid-input paths.

### L3 — Service publication and real use

- Direct Agent Remote Service;
- Relay Agent to LAN target without Agent;
- SSH;
- HTTP;
- HTTPS passthrough;
- Custom TCP;
- Fixed TCP;
- Internet Access with real applications;
- AI/MCP allowed capability;
- external hostname and endpoint use.

### L4 — Policy and live mutation

- ALLOW and DENY for every policy family;
- enable/disable enforcement;
- policy edit while active traffic is running;
- source/destination/service/permission mismatch;
- rule ordering/priority;
- reference protection;
- stale revision and concurrent writer behavior.

### L5 — Daily operations

- show/list/detail/reference views;
- diagnostics;
- audit;
- support bundle;
- revision history/diff;
- endpoint health;
- synchronization;
- Agent pause/resume/restart/autostart;
- operational commands while traffic is active.

### L6 — Failure and recovery

- target outage;
- Agent outage;
- Server outage;
- network interruption;
- DNS/TLS/certificate failure;
- activation failure;
- invalid Bundle;
- authentication failure;
- endpoint exhaustion;
- reconnect storm;
- abrupt/half-close/idle/long-lived TCP behavior;
- false-HEALTHY prevention.

### L7 — Backup, restore, update, reboot

- backup;
- mutate/delete product state;
- restore and functional verification;
- corrupt/invalid restore negative cases;
- Server reboot;
- Agent reboot;
- product update;
- Relay Engine update;
- update failure/recovery;
- prior-stable to candidate upgrade when claimed.

### L8 — Uninstall, reinstall, and cleanup

- Agent uninstall/reinstall;
- Server uninstall/reinstall;
- preserve-state versus purge semantics;
- identity/endpoint behavior after reinstall;
- cleanup of test resources;
- verification that product-owned state only is removed.

## 6. Mandatory feature coverage matrix

Every applicable row must have current-run evidence. A row is not covered merely because a related feature worked.

| Domain | Direct CLI PASS 1 | AI-assisted PASS 2 | Performance / resilience PASS 3 |
| --- | --- | --- | --- |
| Server install / first use | clean install, launch, discovery | AI guides installation and first-use commands without hidden knowledge | startup/restart timing; operational responsiveness |
| Agent install / enrollment | Zero-Touch, manual, bulk; all platforms | AI generates correct enrollment flow and error recovery | parallel enrollment, reconnect storm |
| Managed Hosts | inventory, detail, addresses, lifecycle, delete protection | intent-to-command inventory/admin workflows | inventory responsiveness at host tiers |
| Network Objects / Groups | CRUD, membership, references, invalid cases | single-resource command + multi-resource Bundle | policy lookup under load |
| Service Objects / Groups | CRUD, TCP/UDP/Fixed TCP where supported, references | AI-generated service definitions | mixed service load |
| Remote Services | create/edit/enable/disable/delete, Direct and Relay | AI one-shot + Bundle workflows | forward/reverse/full-duplex, CPS, concurrency, latency |
| Remote Access | no-policy, whitelist, blacklist, ALLOW/DENY, enable/disable | AI creates/modifies/tests policy | policy mutation under active load; deny under load |
| Fixed TCP | pool separation, lifecycle, policy, endpoint continuity | AI creates service + Remote Service correctly | both directions, full duplex, saturation |
| Internet Access | real curl/wget/git/apt or applicable apps, ALLOW/DENY | AI creates objects/rules and explains denial | upload/request + response/download, latency, deny under load |
| AI Identity / Permissions | auth identity, permission objects/groups, logs | AI configures least-privilege policy | concurrent requests, auth latency, audit under load |
| AI/MCP capabilities | allowed and denied tools, file transfer, host/path scope | actual AI-supported workflow and correction loop | request rate/latency and upload/download when supported |
| Public hostname / TLS / certificate | DNS/IP fallback, hostname propagation, certificate lifecycle | AI guides canonical setup without inventing syntax | connection/recovery behavior during DNS/TLS failures |
| ConfigurationBundle | export/test/diff/apply, file/stdin, absent/omitted/no-change, confirmation | natural language -> Bundle -> CLI execution | Bundle test/diff/apply responsiveness under load |
| Revisions / audit / rollback | history, diff, audit, rollback | AI explains and performs intended rollback through CLI | correctness under concurrent traffic |
| Diagnostics / support | diagnostics, support bundle, no secret leakage | AI interprets public diagnostics and proposes public next actions | diagnostics/support generation under traffic |
| Backup / restore | backup, mutate, restore, negative restore | AI constructs recovery procedure using public CLI | backup/recovery while representative load exists |
| Update | product vs engine, prior-stable upgrade, failed update recovery | AI chooses correct update surface | parallel update/reconnect and recovery time |
| Reboot / outage recovery | Server/Agent/target/network interruption | AI-assisted diagnosis after recovery | time-to-connected, inventory, endpoint, HEALTHY, first traffic |
| Uninstall / reinstall | preserve/purge semantics, identity behavior | AI guides correct lifecycle path | post-reinstall reconnection and endpoint continuity |
| Concurrency / race | stale writers, parallel Bundles, parallel lifecycle | conflicting AI-generated operations handled safely | all-host simultaneous traffic and control pressure |
| CLI UX | one-shot, REPL, menu, Wizard, ?, help, Tab | AI uses only canonical discoverable grammar | CLI remains responsive under load |
| Conditional ChatGPT Plugin / MCP relay | real auth/transport path if in scope | actual ChatGPT/Plugin interaction | concurrent auth/tool calls and relay failure behavior |

## 7. CLI usability and discoverability

The test must intentionally behave like a new real operator.

For each workflow record:

~~~text
DISCOVERABLE_WITHOUT_SOURCE=YES|NO
TERMINOLOGY_CLEAR=YES|NO
ERROR_EXPLAINS_NEXT_ACTION=YES|NO
HELP_MENU_TAB_CONSISTENT=YES|NO
REQUIRES_HIDDEN_KNOWLEDGE=YES|NO
AMBIGUOUS_BEHAVIOR=YES|NO
UNNECESSARY_STEPS=
IMPROVEMENT=
~~~

Required public surfaces:

- shell one-shot;
- persistent drlink REPL;
- guided menu;
- Guided Create/Edit Wizard;
- ?;
- help and relevant help topics;
- Tab completion and non-execution safety;
- file ConfigurationBundle;
- stdin ConfigurationBundle.

A command may be observed to be non-mutating, but the E2E run itself must never be described as read-only. If a command documented as observational unexpectedly mutates state, record a defect.

## 8. Direct CLI functional scenarios

The detailed scenario IDs below remain stable for evidence and issue references.

### User scenarios

- U-001: real SSH through a published endpoint, including file transfer.
- U-002: HTTP, HTTPS passthrough, and Custom TCP with real application data.
- U-003: Remote Access no-policy, whitelist, blacklist, ALLOW/DENY, enable/disable.
- U-004: Relay Agent to another LAN target without an Agent.
- U-005: Fixed TCP real bidirectional path and distinct pool.
- U-006: Internet Access with real applications and strict destination/port/source policy.
- U-007: AI/MCP authenticated ALLOW/DENY behavior.
- U-008: active-user continuity across restart and policy change.
- U-009: public hostname, public-IP fallback, and enrollment URL propagation.
- U-010: guided CLI user journey parity.
- U-011: AI/MCP capability matrix and upload/download or file read/write where permitted.
- U-012: Internet Access protocol/application coverage.

### Operator scenarios

- O-001: first-use discovery and role correctness.
- O-002: Zero-Touch enrollment.
- O-003: manual and bulk enrollment.
- O-004: complete Remote Service lifecycle.
- O-005: Server outage, offline Agent change, and synchronization.
- O-006: Agent pause/resume/restart/autostart lifecycle.
- O-007: Agent ConfigurationBundle file/stdin workflows.
- O-008: diagnostics and support bundle.
- O-009: product update versus Relay Engine update.
- O-010: reboot/autostart recovery.
- O-011: Agent uninstall/reinstall.
- O-012: wrong-context command handling.
- O-013: AI-assisted one-resource CLI workflow.
- O-014: AI-assisted multi-resource ConfigurationBundle workflow.
- O-015: Wizard draft/cancel/invalid-input atomicity.

### Administrator scenarios

- A-001: Managed Host inventory and lifecycle.
- A-002: Network Objects and Groups.
- A-003: Service Objects and Groups.
- A-004: Remote Access full policy lifecycle.
- A-005: Internet Access full policy lifecycle.
- A-006: AI Identity, permissions, AI Access, and logs.
- A-007: reference protection.
- A-008: revisions, diff, audit, and rollback.
- A-009: backup and restore.
- A-010: Server ConfigurationBundle atomicity and parity.
- A-011: Server system operations.
- A-012: Zero-Touch capacity and credential security.
- A-013: normal and Fixed TCP endpoint-pool lifecycle.
- A-014: concurrent/stale administrative change protection.
- A-015: fresh Server install, uninstall, and reinstall.
- A-016: AI workflow and CLI traceability audit.
- A-017: concurrent administrative writers.
- A-018: public hostname/bootstrap configuration lifecycle.
- A-019: prior-stable upgrade to candidate when claimed.
- A-020: update failure and recovery.

## 9. Security and failure scenarios

All applicable cases are mandatory and use real product state.

- S-001: every policy family proves both ALLOW and DENY.
- S-002: invalid configuration is atomic.
- S-003: Internet Access escape/bypass attempts fail.
- S-004: secrets do not leak through show, diagnostics, Bundle export, support, audit, or errors.
- S-005: CLI parser, quoting, metacharacter, and shell-safety behavior.
- S-006: role boundary and wrong-context behavior.
- S-007: Server outage.
- S-008: Agent and target outage.
- S-009: runtime activation failure and rollback.
- S-010: backup/restore negative cases.
- S-011: stale synchronized Agent catalog.
- S-012: offline Remote Service deletion.
- S-013: endpoint-pool exhaustion and recovery.
- S-014: names, reserved tokens, duplicate resources, and selector corner cases.
- S-015: network interruption during live traffic.
- S-016: authentication and credential corner cases.
- S-017: DNS, TLS, CA, and public-hostname failure cases.
- S-018: ConfigurationBundle schema and patch corner cases.
- S-019: security-impact confirmation corner cases.
- S-020: boundary/capacity off-by-one cases.
- S-021: failure during mutation or activation.
- S-022: long-lived, half-close, abrupt-close, and idle TCP behavior.
- S-023: no false HEALTHY when public traffic is not actually usable.

When a failure intentionally damages the current host or state, preserve the evidence and proceed with another independent host/lane where possible. Do not repair the product mid-run.

## 10. Parallel multi-host execution

Parallel execution is the default when state dependencies permit it.

Use unique run prefixes for resources so independent lanes do not collide unintentionally.

Required parallel scenarios:

- C-001: all applicable test hosts online simultaneously.
- C-002: parallel enrollment across platforms.
- C-003: parallel Remote Service creation and endpoint allocation.
- C-004: simultaneous real traffic on all hosts.
- C-005: parallel Internet Access from multiple protected sources.
- C-006: parallel AI/MCP identities and calls when applicable.
- C-007: policy mutation while multi-host traffic is active.
- C-008: simultaneous Agent restart/reconnect storm.
- C-009: Server outage with all Agents active.
- C-010: parallel ConfigurationBundle apply.
- C-011: concurrent destructive/race cases.
- C-012: all-host simultaneous reboot recovery.
- C-013: parallel Agent update/restart convergence.
- C-014: mixed parallel lifecycle operations.

Serial execution is used only when tests intentionally share a single destructive global state, such as one Server restore, Server uninstall, or endpoint-pool exhaustion. Serial does not mean non-destructive.

If a shared-state failure blocks one lane, continue independent lanes rather than stopping the run.

## 11. Bidirectional performance contract

Performance is mandatory in FULL_USER_E2E.

If no approved numeric SLO exists, report measured results without inventing a threshold:

~~~text
PERFORMANCE_NUMERIC_QUALIFICATION=MEASURED_NOT_QUALIFIED
~~~

Functional, security, data-integrity, crash, state-corruption, and recovery failures under load are still FAIL.

Default durations unless an approved profile overrides them:

~~~text
WARMUP=60s
STEADY_STATE_EACH_CASE=300s
SOAK=3600s
EXTENDED_SOAK=8h_optional
ENDURANCE_SOAK=24h_optional
~~~

Required measurements:

~~~text
DIRECT_BASELINE=
FORWARD_MBIT_S=
REVERSE_MBIT_S=
FULL_DUPLEX_FORWARD_MBIT_S=
FULL_DUPLEX_REVERSE_MBIT_S=
ATTEMPTED_CPS=
SUCCESSFUL_CPS=
CONCURRENT_CONNECTIONS=
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
RECOVERY_TIME=
~~~

Mandatory performance scenarios:

- P-001: same-environment direct-path baseline where feasible.
- P-002: User -> target sustained throughput.
- P-003: target -> User sustained throughput.
- P-004: simultaneous full-duplex throughput.
- P-005: connection establishment rate / CPS.
- P-006: concurrent active connections.
- P-007: connect/request latency p50/p95/p99.
- P-008: mixed SSH/HTTP/HTTPS/Custom TCP/Fixed TCP workload.
- P-009: multi-host scale at real available tiers; target tiers 1/5/10/30/50 when infrastructure exists.
- P-010: Internet Access request/upload and response/download performance.
- P-011: AI/MCP request rate, latency, concurrent sessions, and file transfer where applicable.
- P-012: connection churn and reconnect storm.
- P-013: mandatory 1-hour soak.
- P-014: backup/restart/recovery under active load.
- P-015: aggregate all-host throughput and fairness.
- P-016: CPS while sustained throughput and policy load are active.
- P-017: recovery-time measurements after Agent/Server/target disruption.
- P-018: public CLI operational responsiveness while traffic is active.
- P-019: optional 8h/24h endurance.
- P-020: network impairment when controllable.
- P-021: saturation and post-saturation recovery.
- P-022: simultaneous control-plane and data-plane pressure.

Performance traffic must use real public endpoints and real application or load clients. A TCP connect-only probe is insufficient for throughput qualification.

Use checksums or application-level integrity verification for file/stream transfers when applicable.

## 12. Platform and topology coverage

Exercise every platform and topology currently claimed by the candidate.

Current platform matrix:

- Ubuntu 24;
- Rocky Linux 8;
- Rocky Linux 9;
- Amazon Linux 2023;
- Windows 10;
- macOS Apple Silicon.

For each platform classify evidence as:

~~~text
PASS_REAL
PASS_SYSTEM_SERVICE
PASS_CONTAINER_ONLY
FAIL
BLOCKED_ENVIRONMENT
NOT_APPLICABLE
~~~

Container/userspace evidence may not be upgraded into a real host PASS.

Topology coverage includes, when claimed by the candidate:

- public IP;
- public DNS hostname;
- single-443 deployment;
- NAT/DNAT;
- Direct Agent local target;
- Relay Agent to LAN target;
- restricted outbound / Internet Access;
- Fixed TCP;
- AI/MCP public endpoint.

At least one full run must bring the available platform matrix online concurrently and exercise the parallel C-* gates.

## 13. Public CLI coverage checklist

This list is a coverage inventory, not a second grammar authority. Exact syntax comes from the current CLI/AI Master and public help.

### Server show

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

### Server set/unset/test

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

test remote-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test internet-access source <SOURCE> destination <DESTINATION> service <SERVICE>
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
test configuration <FILE|->
~~~

### Server system

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

### Agent Host

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

Required aggregate gate:

~~~text
PUBLIC_CLI_COMMAND_COVERAGE=100%
PUBLIC_CLI_SURFACE_COVERAGE=100%
UNEXERCISED_APPLICABLE_PUBLIC_COMMANDS=0
~~~

A command that is genuinely unavailable by role, platform, or excluded feature must be listed with the exact reason rather than silently omitted.

## 14. AI-assisted coverage checklist

PASS 2 must cover the complete operating lifecycle, not only one demonstration prompt.

At minimum execute AI-assisted versions of:

- first-use/installation guidance;
- enrollment;
- Managed Host lookup;
- one Network Object;
- one Network Group;
- one Service Object;
- one Service Group;
- one Remote Service;
- one Remote Access rule;
- one Internet Access rule;
- one AI Identity / Permission / AI Access workflow;
- one diagnostic investigation;
- one update/restart lifecycle action;
- one rollback/recovery workflow;
- one uninstall/reinstall workflow;
- one multi-resource ConfigurationBundle;
- Export -> AI edit -> test -> diff -> apply -> verify;
- one invalid AI-generated command corrected from public CLI feedback;
- one cross-context split workflow where the AI must distinguish Server versus Agent commands.

For each AI-assisted operation record:

~~~text
USER_INTENT=
AI_OUTPUT_TYPE=COMMAND|BUNDLE|GUIDANCE
AI_OUTPUT=
CLI_EXECUTED=
CLI_RESULT=
CORRECTION_REQUIRED=YES|NO
STATE_MATCHES_DIRECT_CLI_INTENT=YES|NO
AMBIGUITY=
UNSAFE_ASSUMPTION=
UX_FINDING=
~~~

The AI may assist. It may not replace execution.

## 15. Conditional ChatGPT Plugin / MCP relay lane

Run this lane only when the Plugin/relay is in acceptance scope and the environment is available.

Verify:

- exact Plugin repository/build identity;
- OAuth 2.1 / owner-consent flow;
- tool discovery;
- real ChatGPT connection;
- DRLink remains the final authorization source;
- ALLOW and DENY through the Plugin path;
- no invented tools;
- no cached authorization bypass;
- secret safety;
- concurrent auth/tool calls;
- durable state and backup/restore where applicable;
- relay failure behavior.

A direct MCP PASS cannot replace a Plugin failure, and a Plugin PASS cannot replace the core CLI and AI-assisted passes.

## 16. Findings: record now, fix later

Record findings immediately, but do not resolve them during the run.

Finding types:

~~~text
DEFECT
SECURITY
PERFORMANCE
UX
DISCOVERABILITY
AMBIGUOUS
DOCUMENTATION
INCONSISTENT_BEHAVIOR
ENVIRONMENT
IMPROVEMENT
~~~

Finding template:

~~~text
FINDING_ID=
SCENARIO_ID=
TYPE=
SEVERITY=P0|P1|P2|UX
ROLE=
HOST=
SOURCE_HEAD=
PRODUCT_VERSION=
COMMAND_OR_ACTION=
EXPECTED=
OBSERVED=
USER_IMPACT=
REPRODUCIBLE=YES|NO|UNKNOWN
BLOCKS=
DEPENDENT_SCENARIOS=
EVIDENCE=
NOTES=
~~~

When a problem blocks later work:

~~~text
CURRENT_SCENARIO=FAIL
DEPENDENT_SCENARIO=BLOCKED_BY_PRIOR_FAILURE
BLOCKED_BY=<FINDING_ID>
CONTINUE_INDEPENDENT_TESTS=YES
FIX_NOW=NO
~~~

At the end of the run, consolidate multiple symptoms that share one root cause before creating fix work.

## 17. Result states and evidence

Every scenario result is one of:

~~~text
PASS
FAIL
BLOCKED_BY_PRIOR_FAILURE
BLOCKED_ENVIRONMENT
NOT_APPLICABLE
NOT_RUN_BY_SCOPE
~~~

Rules:

- PASS requires current-run evidence.
- release-qualifying PASS requires the exact candidate build.
- BLOCKED_BY_PRIOR_FAILURE is used when a recorded product failure prevents the scenario from executing.
- BLOCKED_ENVIRONMENT is used only when required external infrastructure is genuinely unavailable.
- NOT_APPLICABLE requires an explicit product/platform reason.
- NOT_RUN_BY_SCOPE is allowed only for an explicitly narrowed request.
- FULL_USER_E2E cannot be PASS while any mandatory applicable scenario is FAIL, blocked, or not run.
- numeric performance remains MEASURED_NOT_QUALIFIED when no approved numeric SLO exists.
- an earlier failure does not justify stopping unrelated tests.

Per-scenario evidence:

~~~text
SCENARIO_ID=
PASS_NUMBER=CLI_DIRECT|AI_ASSISTED|PERFORMANCE
ROLE=
HOST=
START_UTC=
END_UTC=
SOURCE_HEAD=
PRODUCT_VERSION=
COMMANDS_OR_ACTIONS=
EXPECTED=
OBSERVED=
RESULT=
BLOCKED_BY=
FINDINGS=
EVIDENCE_PATHS=
~~~

Run-level identity:

~~~text
TEST_RUN_ID=
START_UTC=
END_UTC=
REPOSITORY=
BRANCH=
SOURCE_HEAD=
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
EVIDENCE_ROOT=
~~~

Never paste live Zero-Touch secrets, OAuth tokens, TLS private keys, ACME keys, passwords, or other reusable credentials into findings.

## 18. Final report

Every full run ends with a consolidated report.

~~~text
PHASE=FULL_USER_E2E
EXECUTOR=ChatGPT
FINAL_AUDITOR=ChatGPT
CURSOR_EXECUTED_USER_E2E=NO
FIXES_PERFORMED_DURING_RUN=NO

SOURCE_HEAD=
PRODUCT_VERSION=
FINAL_STATUS=PASS|PARTIAL|FAIL

CLI_DIRECT_FUNCTIONAL=
AI_ASSISTED_FUNCTIONAL=
BIDIRECTIONAL_PERFORMANCE=
USER_LIFECYCLE=
OPERATOR_LIFECYCLE=
ADMIN_LIFECYCLE=
SECURITY_FAILURE=
MULTI_PLATFORM=
TOPOLOGY_MATRIX=
PARALLEL_MULTI_HOST=

PUBLIC_CLI_COMMAND_COVERAGE=
PUBLIC_CLI_SURFACE_COVERAGE=
AI_ASSISTED_WORKFLOW_COVERAGE=
UNEXERCISED_APPLICABLE_COMMANDS=

REMOTE_ACCESS_REAL_TRAFFIC=
FIXED_TCP_REAL_TRAFFIC=
INTERNET_ACCESS_REAL_TRAFFIC=
AI_MCP_REAL_TRAFFIC=
ZERO_TOUCH=
CONFIGURATION_BUNDLE=
BACKUP_RESTORE=
REBOOT_RECOVERY=
UPDATE_RECOVERY=
UNINSTALL_REINSTALL=
ENDPOINT_CONTINUITY=

THROUGHPUT_FORWARD=
THROUGHPUT_REVERSE=
THROUGHPUT_FULL_DUPLEX=
CPS=
CONCURRENT_CONNECTIONS=
CONNECT_P95=
CONNECT_P99=
SOAK=
RESOURCE_STABILITY=
RECOVERY_TIME=

P0_COUNT=
P1_COUNT=
P2_COUNT=
UX_COUNT=
DOC_COUNT=
PERF_COUNT=
BLOCKED_BY_PRIOR_FAILURE_COUNT=
BLOCKED_ENVIRONMENT_COUNT=
FINDINGS=
BLOCKERS=
EVIDENCE_ROOT=
~~~

After this report is complete:

~~~text
NEXT=consolidate findings -> create/update fix work -> Cursor implementation if required -> ChatGPT verification -> rerun affected/full qualification
~~~

## 19. Release qualification

When release policy requires two Full Real E2E passes:

~~~text
PASS1_HEAD == PASS2_HEAD == FINAL_QUALIFIED_HEAD
~~~

Both passes use this document.

A product/dependency/generated-runtime change that affects the candidate invalidates the affected qualification pass according to docs/RELEASE_VALIDATION.md.

A documentation-only clarification may still change Git HEAD; record source/product build identities separately so release provenance remains explicit.

## 20. Maintenance rule

Whenever a public CLI command, feature, supported platform, topology, policy semantic, enrollment workflow, Remote Service lifecycle, Internet Access behavior, AI/MCP capability, ConfigurationBundle behavior, backup/restore behavior, update behavior, uninstall behavior, or release gate changes, this document must be reviewed in the same workstream.

The durable execution invariant is:

~~~text
FULL_USER_E2E
-> use designated real test servers and clients
-> allow destructive real lifecycle testing
-> install Server and Agents for real
-> PASS 1: test all applicable functions through public CLI
-> PASS 2: repeat applicable workflows with AI assistance and execute the generated CLI/Bundle
-> PASS 3: run forward, reverse, and full-duplex performance/resilience
-> act as User, Operator, and Administrator through the full product lifecycle
-> run independent hosts/scenarios in parallel
-> break Server/Agent/target/network state where scenarios require it
-> record defects, blockers, ambiguity, confusion, and improvements immediately
-> never fix product defects during the active run
-> continue all independent tests after failures
-> consolidate findings only after the planned run is exhausted
-> then enter the fix/verify/rerun loop
~~~
