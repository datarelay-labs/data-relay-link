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

## 0. Execution entry point

This file is an executable test contract, not a prompt template.

A user instruction equivalent to any of the following is sufficient to start the full run:

~~~text
GitHub의 USER_E2E_SCENARIOS.md 수행해
USER_E2E_SCENARIOS.md 실행해
DRLink Full User E2E 시작
~~~

When invoked this way, the executor must not ask the user to restate this document, copy scenarios into the chat, provide a separate run plan, or manually select hosts unless a fact cannot be discovered from the repository or test environment.

The executor must autonomously:

1. read the latest applicable USER_E2E_SCENARIOS.md from the Data Relay Link candidate workstream;
2. read only the referenced canonical documents needed to resolve current CLI grammar, release identity, or qualification rules;
3. resolve the exact product candidate branch/HEAD/build using the active release workstream; a documentation-only E2E-contract branch does not silently become the product candidate;
4. on the DRLink development server, read `~/.ssh/config` and use its concrete SSH Host aliases as the candidate host inventory; probe them and classify every currently reachable host by role, platform, topology, privilege, and destructive-test suitability;
5. acquire a run lock so another destructive FULL_USER_E2E cannot silently use the same Server/Agent fleet at the same time;
6. create a new run identity, evidence root, and unique resource prefix;
7. capture pre-run host/time/network/product-state inventory, then normalize every designated mutable test host to the clean baseline defined in this document;
8. install any ordinary non-product test utilities needed for traffic generation, metrics, checksums, or network fault injection;
9. install the exact candidate cleanly and record installed product identity;
10. map this document's scenarios to the available environment;
11. start every independent executable lane in parallel, using all suitable available hosts;
12. keep representative real traffic active while executing live policy, Agent, Remote Service, Object/Group, Bundle, diagnostics, lifecycle, failure, and recovery changes where this document requires it;
13. execute PASS 1 Direct CLI, PASS 2 AI-assisted, and PASS 3 bidirectional performance/resilience as defined here;
14. record findings and dependent blockers without fixing product defects during the active run;
15. continue until every currently executable scenario has been attempted and all coverage limitations are recorded;
16. produce the final report defined by this document;
17. release the run lock only after evidence is durable;
18. only after the run is exhausted, consolidate findings and enter the engineering fix/verify/rerun workflow.

Default behavior is execution, not explanation.

~~~text
READ_DOCUMENT_AND_EXECUTE=YES
ASK_USER_TO_RESTATE_RULES=NO
ASK_FOR_CONFIRMATION_BEFORE_START=NO
PLAN_ONLY_RESPONSE=NO
USE_AVAILABLE_REAL_HOSTS=YES
PRE_RUN_CLEAN_NORMALIZATION=YES
AUTO_INSTALL_TEST_UTILITIES=YES
RUN_LOCK_REQUIRED=YES
UNIQUE_RESOURCE_PREFIX_REQUIRED=YES
PARALLEL_BY_DEFAULT=YES
CONTINUE_AFTER_INDEPENDENT_FAILURES=YES
FIX_DURING_ACTIVE_RUN=NO
STOP_WHEN_CURRENTLY_EXECUTABLE_SCENARIOS_EXHAUSTED=YES
~~~

If the user explicitly narrows the scope, execute only that requested subset. Otherwise the trigger means FULL_USER_E2E.

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

### 2.1.1 Pre-run clean normalization

A new FULL_USER_E2E must not inherit success/failure state from a previous run.

Before installing the exact candidate, every designated mutable Server/Agent/client host must be inspected for stale DRLink test state.

Record a pre-clean snapshot:

~~~text
HOST=
REACHABLE=
SUDO_OR_ADMIN=
TIME_UTC=
DRLINK_INSTALLED=
DRLINK_VERSION=
DRLINK_SERVICES=
DRLINK_PROCESSES=
DRLINK_LISTENERS=
DRLINK_CONFIG_STATE=
DRLINK_RUNTIME_STATE=
PREVIOUS_E2E_RESOURCES=
CLEANUP_REQUIRED=YES|NO
~~~

If previous testing left DRLink installed, partially installed, enrolled, running, failed, or carrying prior test configuration/state, normalize the host before the new run.

Preferred cleanup order:

1. use the installed product's documented public uninstall/purge path when it is functional;
2. verify product-owned services/processes/listeners have stopped;
3. remove only stale product-owned test state that the documented uninstall/purge contract says should be removable;
4. if a broken/partial prior installation prevents public uninstall, perform pre-run lab normalization with normal OS/package/service tools, restricted strictly to DRLink-owned packages, units, processes, configuration, state, runtime, logs, and test artifacts;
5. reboot the designated test host when required to prove that stale processes/mounts/listeners are gone;
6. verify the clean baseline before candidate installation.

Pre-run lab normalization is environment preparation, not qualification evidence for the uninstall feature. The actual uninstall/reinstall scenarios later in the run must still exercise and grade the public product lifecycle.

Never delete unrelated application, user, operating-system, rescue, or production data merely to make a host clean.

A host is considered clean enough to begin candidate installation when:

~~~text
NO_PREVIOUS_DRLINK_PROCESS=YES
NO_PREVIOUS_DRLINK_SERVICE_ACTIVE=YES
NO_STALE_DRLINK_LISTENER=YES
NO_PREVIOUS_E2E_CONTROL_STATE=YES
NO_PREVIOUS_E2E_ENROLLMENT_IDENTITY=YES
NO_PREVIOUS_E2E_RUNTIME_STATE=YES
UNRELATED_HOST_STATE_PRESERVED=YES
~~~

If the host cannot be safely normalized without touching unrelated/production/rescue state, exclude it from destructive use and continue with the remaining hosts.

### 2.1.2 Autonomous preflight defaults

FULL_USER_E2E uses these defaults so execution does not require another prompt:

~~~text
RUN_ID=drlink-e2e-<UTC_TIMESTAMP>
RESOURCE_PREFIX=e2e-<RUN_ID>-
EVIDENCE_ROOT=$HOME/e2e-reports/<RUN_ID>
RUN_LOCK=$HOME/.cache/drlink-full-user-e2e.lock
HOST_CLOCK_CHECK=REQUIRED
SUDO_OR_ADMIN_PROBE=REQUIRED
TEST_UTILITY_INSTALL=ALLOWED
TEST_UTILITY_INSTALL_SCOPE=NON_PRODUCT_ONLY
SECRET_LOGGING=FORBIDDEN
~~~

Rules:

- create the evidence root before destructive work;
- record command/action output with host and UTC timestamps;
- check host clocks well enough to correlate concurrent events; record material skew;
- probe sudo/administrator capability before assigning destructive scenarios;
- ordinary load/measurement/fault-injection tools may be installed when absent;
- installing a test utility must not change DRLink product code or authoritative state;
- use the unique resource prefix for temporary Objects, Groups, Rules, services, identities, files, and load-test names where the product allows naming;
- do not run two destructive FULL_USER_E2E executions against the same shared Server/fleet without explicit isolation;
- never persist reusable credentials, enrollment secrets, OAuth tokens, or private keys in evidence.

### 2.1.3 Product candidate resolution

The E2E contract revision and the product candidate revision may differ.

Resolve and record both:

~~~text
E2E_CONTRACT_REF=
E2E_CONTRACT_HEAD=
PRODUCT_CANDIDATE_BRANCH=
PRODUCT_CANDIDATE_HEAD=
PRODUCT_CANDIDATE_BUILD=
~~~

A documentation-only branch or PR that changes this test contract must not silently change the product bytes being qualified.

Candidate precedence:

1. an exact candidate SHA explicitly pinned by the active release workstream;
2. otherwise the exact HEAD identified by the active release-closure Work Packet / release-validation state;
3. otherwise the exact HEAD of the release candidate/base workstream associated with the E2E contract.

If multiple different product HEADs are simultaneously presented as the active release candidate and repository evidence cannot resolve the conflict, record `CANDIDATE_IDENTITY_CONFLICT` before destructive qualification. Do not combine evidence from different product candidates into one qualifying run.

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

All DRLink product management, configuration, supported product lifecycle, diagnostics, recovery, and inspection actions used to exercise DRLink behavior must use the public drlink CLI.

Black-box test-harness actions are allowed outside drlink when they represent the environment rather than a hidden product-management path. Examples include generating application/load traffic, rebooting or powering a designated test host, stopping/starting a target application, disconnecting a network interface, applying controlled latency/loss, occupying an external port to create a collision, filling a bounded disposable test filesystem, collecting OS CPU/RSS/FD/network metrics, or corrupting a copy of a backup archive for a negative restore test.

These OS/network actions may inject failures or measure behavior. They may not configure, repair, bypass, or directly mutate DRLink authoritative state to obtain PASS.

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

- discover candidate hosts from the development server's `~/.ssh/config`;
- verify test host identity, OS, architecture, privilege, network, DNS, clock, and topology;
- detect and clean previous E2E/DRLink state on designated mutable hosts before the new candidate install;
- clean Server install from the exact candidate;
- first launch and public CLI discovery;
- clean Agent installs on every currently available applicable platform; record unavailable claimed platforms as coverage limitations;
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
| Agent install / enrollment | Zero-Touch, manual, bulk on all currently available applicable platforms | AI generates correct enrollment flow and error recovery | parallel enrollment, reconnect storm |
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

## 10. Parallel multi-host and live-change execution

Parallel execution is the default. FULL_USER_E2E should resemble a live environment, not a sequence of isolated laboratory checks.

Use every suitable real test host that is available at run time. Host count is adaptive:

~~~text
AVAILABLE_HOST_COUNT=N
PARALLEL_HOST_TARGET=N
RUN_WITH_AVAILABLE_HOSTS=YES
MISSING_EXTRA_HOSTS_BLOCK_RUN=NO
~~~

If 2 hosts are available, run the parallel cases with 2. If 6 are available, use 6. If more hosts become available, use more. Do not fabricate 10/30/50 hosts and do not delay the base FULL_USER_E2E merely because a larger fleet is unavailable.

Use unique run prefixes for resources so independent lanes do not collide accidentally. Shared destructive state is coordinated intentionally; unrelated work continues in parallel.

### 10.1 Continuous traffic backbone

Once usable data paths exist, keep representative traffic running while Operator and Administrator scenarios continue.

Maintain as many of the following concurrently as the available topology permits:

- long-lived SSH/TCP sessions;
- repeated short-connection HTTP/HTTPS or Custom TCP traffic;
- sustained bulk-transfer or throughput streams;
- Internet Access request/response traffic;
- AI/MCP requests when that feature is in scope.

During this traffic, perform real control/lifecycle changes instead of pausing traffic for every administration step.

For every event record:

~~~text
EVENT=
EVENT_START_UTC=
EVENT_END_UTC=
TRAFFIC_BEFORE=
TRAFFIC_DURING=
TRAFFIC_AFTER=
NEW_CONNECTION_RESULT=
ESTABLISHED_CONNECTION_RESULT=
ERROR_SPIKE=
UNAUTHORIZED_ALLOW_COUNT=
UNEXPECTED_DENY_COUNT=
ENDPOINT_CHANGED=YES|NO
RECOVERY_SECONDS=
DATA_INTEGRITY_ERRORS=
~~~

The key invariant is that a change on one host/resource must not corrupt, reroute, authorize, deny, rename, or release an unrelated live path.

### 10.2 Required parallel scenarios

Execute each scenario with the maximum suitable host/resource count available at that moment.

- C-001: all currently available applicable test hosts online simultaneously.
- C-002: parallel enrollment across the available platforms/hosts.
- C-003: parallel Remote Service creation and endpoint allocation.
- C-004: simultaneous real traffic on all usable hosts.
- C-005: parallel Internet Access from all suitable protected sources.
- C-006: parallel AI/MCP identities and calls when applicable.
- C-007: Remote Access / Internet Access / AI Access policy mutation while live traffic continues.
- C-008: simultaneous Agent restart/reconnect storm across the available Agent fleet.
- C-009: Server outage with multiple active Agents and user sessions.
- C-010: parallel ConfigurationBundle test/diff/apply on independent resources.
- C-011: concurrent destructive/race cases and stale writers.
- C-012: simultaneous reboot recovery across all currently available approved Agent hosts.
- C-013: parallel Agent update/restart convergence.
- C-014: mixed parallel lifecycle operations on different hosts.
- C-015: continuous traffic + repeated policy churn: rule add/edit/delete, whitelist/blacklist, enforcement enable/disable, policy reset; measure established-session and new-connection behavior separately.
- C-016: continuous traffic + fleet join/leave churn: enroll a new Agent, publish service, generate traffic, remove/uninstall another Agent, and verify unaffected hosts continue without endpoint or policy cross-talk.
- C-017: continuous traffic + Remote Service churn: create/enable/disable/edit/delete services on one Agent while unrelated services on other Agents remain active.
- C-018: endpoint allocation/reclamation under live traffic: create/delete/recreate services and verify no premature endpoint reuse, duplicate allocation, cross-target routing, or stale HEALTHY state.
- C-019: real mixed-role window: Users transfer data while Operators change Agent/Remote Service state and Administrators change policy, run diagnostics/audit, test/diff Bundles, and perform supported backup activity.
- C-020: Managed Host deletion/re-enrollment corner case: delete/revoke a host while its Agent is connected, observe reconnect behavior, then re-enroll through the documented path and verify identity/authorization semantics.
- C-021: staged failure cascade under traffic: independently fail target -> Agent -> network path -> Server, recover each layer, and measure unrelated-path continuity and final state convergence.
- C-022: enrollment churn under service load: issue/redeem/revoke/expire tickets and add/remove Agents while unrelated Remote Access/Internet Access traffic remains active.
- C-023: concurrent direct-CLI and AI-assisted administration on independent resources, proving both paths converge through the same product semantics and do not lose updates or bypass revision protection.
- C-024: live Object/Group membership mutation: add/remove Network Group, Service Group, and Permission Group members while dependent traffic/calls continue; verify only newly affected connections/calls change according to policy and references remain consistent.
- C-025: live Service Object / Remote Service edit: change destination/service parameters permitted by contract while existing traffic and unrelated endpoints remain active; verify endpoint continuity for same-pool edits and deterministic rejection for invalid cross-pool edits.
- C-026: AI credential lifecycle under load: rotate/revoke/expire a credential while concurrent authorized AI/MCP calls are running; verify subsequent calls re-evaluate authentication/authorization and no cached authorization bypass occurs.
- C-027: diagnostics/audit/support pressure during mutation: generate high event/audit volume while policies and Agents churn, then run diagnostics/audit/support-bundle and verify responsiveness, ordering/attribution, bounded output, and secret safety.

### 10.3 Parallelism rule

Run independent scenario lanes concurrently whenever hosts/resources do not require exclusive ownership of the same destructive global state.

Serial execution is limited to operations that truly require exclusive ownership of one shared global state, for example one Server restore, Server uninstall/reinstall, or deliberate exhaustion of one endpoint pool. Serial does not mean non-destructive.

Do not serialize merely because parallel execution is harder. Concurrency itself is part of the product test.

If a shared-state failure blocks one lane, continue every independent lane rather than stopping the run.

## 11. Bidirectional performance, churn, and resilience contract

Performance is mandatory in FULL_USER_E2E and must be measured during both steady state and real operational change.

If no approved numeric SLO exists, report measured results without inventing a threshold:

~~~text
PERFORMANCE_NUMERIC_QUALIFICATION=MEASURED_NOT_QUALIFIED
~~~

Functional, security, data-integrity, crash, state-corruption, authorization, and recovery failures under load are always FAIL.

Default durations unless an approved profile overrides them:

~~~text
WARMUP=60s
STEADY_STATE_EACH_CASE=300s
MIXED_OPERATION_WINDOW=1800s
SOAK=3600s
EXTENDED_SOAK=8h_optional
ENDURANCE_SOAK=24h_optional
~~~

Required directions:

~~~text
FORWARD=external/protected user -> target
REVERSE=target/Internet response -> user
FULL_DUPLEX=both directions simultaneously
~~~

For Internet Access, REVERSE means legitimate response/download traffic belonging to the outbound application flow. Do not invent an unsolicited inbound Internet path that the product does not claim.

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
CONTROL_COMMAND_P95_MS=
ERROR_RATE=
RECONNECT_RATE=
DROPPED_EXISTING_CONNECTIONS=
FAILED_NEW_CONNECTIONS=
UNAUTHORIZED_ALLOW_COUNT=
UNEXPECTED_DENY_COUNT=
ENDPOINT_CHANGES=
SERVER_CPU_AVG_MAX=
SERVER_RSS_AVG_MAX=
SERVER_FD_AVG_MAX=
SERVER_DISK_GROWTH=
AGENT_CPU_AVG_MAX=
AGENT_RSS_AVG_MAX=
AGENT_FD_AVG_MAX=
AGENT_DISK_GROWTH=
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
- P-009: scale at the maximum real host count available during the run. Measure at 1 host and at all available hosts; add intermediate points when convenient. Missing additional hosts do not block FULL_USER_E2E. Larger 10/30/50-host tests are a separate scale profile only when that scale is explicitly claimed or provisioned.
- P-010: Internet Access request/upload and response/download performance.
- P-011: AI/MCP request rate, latency, concurrent sessions, and file transfer where applicable.
- P-012: connection churn and Agent reconnect storm.
- P-013: mandatory 1-hour mixed-traffic soak using the available fleet.
- P-014: backup/restart/recovery under active load.
- P-015: aggregate all-available-host throughput and fairness.
- P-016: CPS while sustained throughput and policy load are active.
- P-017: recovery-time measurements after Agent/Server/target disruption.
- P-018: public CLI operational responsiveness while traffic is active.
- P-019: optional 8h/24h endurance.
- P-020: controlled latency/loss/jitter/bandwidth/partition characterization when the available test infrastructure can inject it safely.
- P-021: saturation and post-saturation recovery.
- P-022: simultaneous control-plane and data-plane pressure.
- P-023: sustained traffic while policy rules are repeatedly added, edited, disabled, enabled, reset, and removed; measure throughput/latency/error spikes plus existing-session versus new-connection semantics.
- P-024: sustained traffic while Agents join and leave: Zero-Touch enrollment, new service creation, Agent pause/restart, Managed Host removal, uninstall/reinstall, and re-enrollment on available hosts.
- P-025: sustained traffic while Remote Services and endpoint allocations churn; measure endpoint reuse delay, failed/incorrect routing, allocation errors, and recovery.
- P-026: 30-minute mixed-role operational window combining User traffic, Operator lifecycle work, Administrator policy/Bundle/diagnostic work, and at least one controlled failure/recovery event.
- P-027: post-churn recovery and leak check: after load and lifecycle churn stop, verify CPU/RSS/FD/disk/log growth stabilizes, endpoints are not leaked, no stale Agents/services remain falsely healthy, and normal traffic resumes.
- P-028: security-under-load window: continuously attempt representative denied Remote Access, Internet Access, and AI/MCP operations while allowed traffic and configuration churn are active; unauthorized success count must remain zero.
- P-029: Object/Group mutation under load: measure policy-evaluation latency/error spikes while Network/Service/Permission memberships change and confirm no stale membership authorization.
- P-030: credential rotation/revocation under AI/MCP load: measure time to effective denial, in-flight behavior, authentication latency, and unauthorized success count.
- P-031: endpoint continuity during allowed same-pool service edits and deterministic failure/recovery for rejected cross-pool edits while traffic remains active.

Performance traffic must use real public endpoints and real application or load clients. A TCP connect-only probe is insufficient for throughput qualification.

Use checksums or application-level integrity verification for file/stream transfers when applicable.

Measure before, during, and after every disruptive event. A single final average must not hide a short authorization bypass, connection-loss spike, endpoint cross-talk, or slow recovery.

## 12. Platform, topology, and execution feasibility

Use the real test environment that exists at run time. The base FULL_USER_E2E is adaptive to available hosts; it does not require provisioning an arbitrary fixed host count before testing can begin.

### 12.1 Pre-run feasibility inventory

The runtime host inventory SSOT is the OpenSSH client configuration on the DRLink development server:

~~~text
HOST_INVENTORY_SOURCE=~/.ssh/config
HOST_DISCOVERY_MODE=SSH_CONFIG_ALIASES
USE_HARDCODED_HOST_LIST=NO
USE_HOSTS_OUTSIDE_SSH_CONFIG=NO
~~~

At the start of every run:

1. read `~/.ssh/config` on the development server;
2. enumerate concrete `Host` aliases defined there, ignoring wildcard-only patterns such as `*` or pattern entries that are not directly connectable aliases;
3. probe each alias through normal SSH resolution/configuration rather than reconstructing addresses manually;
4. treat successfully reachable aliases as the current available-host pool;
5. identify each reachable host's hostname, OS/platform, architecture, network role, and whether DRLink Server/Agent/client/load-generator/target use is applicable;
6. record unreachable aliases as current environment coverage information and continue;
7. do not invent, reuse from memory, or hardcode a separate host list when `~/.ssh/config` is available.

Reachability makes a host available for consideration, but destructive scenarios must still remain within the designated DRLink test scope. A host that is clearly production, rescue-only, or unrelated infrastructure is inventoried but excluded from destructive mutation unless it is explicitly designated for the current test run.

This SSH-config inventory is refreshed at the beginning of each FULL_USER_E2E run because hosts may be added, removed, renamed, or temporarily unavailable between runs.

Inventory all resulting test assets and classify each planned scenario:

~~~text
EXECUTABLE_NOW
EXECUTABLE_WITH_NORMAL_TEST_SETUP
COVERAGE_LIMITATION
CONDITIONAL_FEATURE
NOT_APPLICABLE
~~~

Normal test setup includes installing a load generator, starting a disposable target service, creating test data, or enabling supported OS/network test facilities. It must not patch DRLink product code or mutate private DRLink state.

A scenario is not considered impossible merely because it is destructive, long-running, or requires coordination.

### 12.2 Available-host rule

~~~text
USE_ALL_SUITABLE_AVAILABLE_HOSTS=YES
MINIMUM_FIXED_AGENT_COUNT=NONE
MISSING_HOST_COUNT_IS_PRODUCT_FAILURE=NO
MISSING_HOST_COUNT_BLOCKS_BASE_E2E=NO
~~~

Examples:

- 2 suitable Agents available -> execute parallel/fleet scenarios with 2.
- 6 suitable Agents available -> execute them with 6.
- 12 suitable Agents available -> execute them with 12.
- one supported OS is temporarily unavailable -> continue on all other hosts and record the platform coverage limitation.

Do not simulate extra hosts merely to satisfy a number unless simulation/container scale is itself the selected test profile. Do not report unavailable hosts as product failures.

### 12.3 Platform coverage

Current candidate platform claims include:

- Ubuntu 24;
- Rocky Linux 8;
- Rocky Linux 9;
- Amazon Linux 2023;
- Windows 10;
- macOS Apple Silicon.

For each platform record:

~~~text
PASS_REAL
FAIL_PRODUCT
COVERAGE_LIMITATION_ENVIRONMENT
NOT_APPLICABLE
~~~

A temporarily unavailable platform does not stop the rest of FULL_USER_E2E. If release policy separately requires evidence for every claimed platform before publication, that is a release-qualification coverage gap, not a reason to stop the active test run.

### 12.4 Topology coverage

Exercise every currently available/claimed topology that can be reached from the test environment:

- public IP;
- public DNS hostname;
- single-443 deployment;
- NAT/DNAT;
- Direct Agent local target;
- Relay Agent to LAN target;
- restricted outbound / Internet Access;
- Fixed TCP;
- AI/MCP public endpoint.

Unavailable topology is recorded as COVERAGE_LIMITATION with the exact missing prerequisite. Continue the remaining topology tests.

### 12.5 Inherently conditional scenarios

The following are conditional on external capability and should not make the base run impossible:

- ChatGPT Plugin/relay: run when that integration is in acceptance scope and the real account/connector surface is available.
- public DNS/TLS/ACME: run when the candidate claims that path and DNS/ports are available.
- prior-stable upgrade: run when the release claims upgrade support and the prior stable artifact is available.
- controlled network impairment: run when the available host/network can safely inject it.
- 8h/24h endurance: optional unless explicitly selected; the 1-hour soak remains the base requirement.
- direct-path performance baseline: if a comparable bypass is physically unavailable, record BASELINE_UNAVAILABLE with topology evidence.
- large-fleet 10/30/50 scale: separate scale qualification when explicitly selected; never a prerequisite for the adaptive available-host base E2E.

At least one run window should bring all currently available suitable hosts online concurrently and exercise the C-* mixed-operation gates.

### 12.6 Black-box fault injection rule

Failure scenarios must be executable from outside the product whenever possible.

Preferred fault sources include:

- host reboot/power cycle;
- service/target stop;
- network disconnect, route/firewall impairment, latency/loss/jitter;
- DNS resolution failure or wrong hostname;
- port collision;
- target refusal/timeout;
- bounded disk-space or filesystem-permission failure on a disposable test path;
- corrupt backup copy;
- expired/revoked/invalid external credential where the public workflow supports it.

Do not require a private debug hook or direct database/runtime-state edit merely to inject a failure.

If a specific internal failure phase cannot be deterministically triggered from public/black-box surfaces, run the nearest externally reproducible failure/recovery case and record:

~~~text
FAULT_INJECTION_LIMITATION=<exact internal phase>
BLACK_BOX_EQUIVALENT=<scenario actually executed>
PRODUCT_FAILURE=NO_UNLESS_OBSERVED
~~~

This is a coverage limitation, not a reason to stop other testing.

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
PRE_RUN_CLEAN_NORMALIZATION=
CANDIDATE_IDENTITY_RESOLVED=
RUN_LOCK_USED=
RESOURCE_PREFIX=

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
COVERAGE_LIMITATION
NOT_APPLICABLE
NOT_RUN_BY_SCOPE
~~~

Rules:

- PASS requires current-run evidence.
- release-qualifying PASS requires the exact candidate build.
- BLOCKED_BY_PRIOR_FAILURE is used when a recorded product failure prevents the scenario from executing.
- COVERAGE_LIMITATION means a platform, topology, external integration, or larger scale tier was unavailable in the current environment. It is not a product FAIL and does not stop the base FULL_USER_E2E run.
- NOT_APPLICABLE requires an explicit product/feature reason.
- NOT_RUN_BY_SCOPE is allowed only for an explicitly narrowed request.
- FULL_USER_E2E functional PASS is invalid when an executable mandatory scenario FAILs or is blocked by a product failure.
- Missing additional host count alone never changes PASS to FAIL/BLOCKED; report AVAILABLE_HOST_COUNT and MAX_PARALLEL_HOSTS_USED.
- Release publication may still require closing specific platform/topology coverage limitations defined by release policy.
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
RESOURCE_PREFIX=
E2E_CONTRACT_REF=
E2E_CONTRACT_HEAD=
PRODUCT_CANDIDATE_BRANCH=
PRODUCT_CANDIDATE_HEAD=
RUN_LOCK=
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
AVAILABLE_HOST_COUNT=
MAX_PARALLEL_HOSTS_USED=
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
BASE_E2E_EXECUTION_STATUS=PASS|FAIL
RELEASE_COVERAGE_STATUS=COMPLETE|LIMITED

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
AVAILABLE_HOST_COUNT=
MAX_PARALLEL_HOSTS_USED=
MAX_REAL_SCALE_TESTED=
UNTESTED_SCALE_CLAIMS=
PLATFORM_COVERAGE_LIMITATIONS=
TOPOLOGY_COVERAGE_LIMITATIONS=

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
LIVE_POLICY_CHURN=
LIVE_AGENT_JOIN_LEAVE=
LIVE_REMOTE_SERVICE_CHURN=
LIVE_OBJECT_GROUP_CHURN=
AI_CREDENTIAL_CHURN=
MIXED_ROLE_OPERATION_WINDOW=
SECURITY_UNDER_LOAD=

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
COVERAGE_LIMITATION_COUNT=
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
-> discover candidate hosts from the development server's ~/.ssh/config and use every suitable reachable host at run time; never block the base run for lack of an arbitrary host count
-> run independent hosts/scenarios in parallel
-> keep representative traffic active while policies, Agents, Remote Services, Bundles, and lifecycle state change
-> break Server/Agent/target/network state where scenarios require it
-> record defects, blockers, ambiguity, confusion, and improvements immediately
-> never fix product defects during the active run
-> continue all independent tests after failures
-> consolidate findings only after the planned run is exhausted
-> then enter the fix/verify/rerun loop
~~~
