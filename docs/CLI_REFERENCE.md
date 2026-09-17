# Data Relay Link — CLI Reference

> **Document role:** Canonical v2.4.0 target direct-command grammar
> **Status:** Architecture-frozen target; current development implementation may lag until the implementation phase completes
> **Primary CLI:** `drlink`
> **UX architecture:** `Data Relay Link CLI Information Architecture.md`

## 1. Grammar

Canonical direct form:

```text
drlink <ACTION> <RESOURCE> [TARGET] [PROPERTY] [VALUE...]
```

Inside the persistent REPL, omit the leading `drlink`.

Canonical roots:

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

Normal public grammar does not use legacy `acl`, `service-profile`, or `internet-profile` resources.

## 2. Common discovery

```text
show status
show version
help
help commands
menu
```

## 3. Clients

```text
show clients
show client <CLIENT>
show client <CLIENT> services
show client <CLIENT> groups
show client <CLIENT> endpoint
show client <CLIENT> addresses

set client <CLIENT> label <TEXT>
set client <CLIENT> description <TEXT>
set client <CLIENT> tag <KEY=VALUE>
unset client <CLIENT> tag <KEY>

unset client <CLIENT>
```

`unset client <CLIENT>` is destructive server-side removal and requires confirmation in interactive use. Exact lifecycle effects must preserve the Product Master contract for service reservations, identity, and orphaned policy references.

Management trust revocation remains a distinct lifecycle operation if the implementation exposes it as a public direct command:

```text
system revoke client <CLIENT>
```

The implementation must not overload `unset` to mean both revoke and remove.

## 4. Client Groups

```text
show client-groups
show client-group <GROUP>

set client-group <GROUP>
set client-group <GROUP> description <TEXT>
set client-group <GROUP> member <CLIENT>

unset client-group <GROUP> member <CLIENT>
unset client-group <GROUP>
```

Client Group is operational organization and an AI target selector. It is not an Object Group.

## 5. Enrollments

```text
show enrollments
show enrollment <ID>

set enrollment manual
set enrollment zero-touch

unset enrollment <ID>
```

Guided onboarding remains preferred for Zero-Touch because it collects platform, client identity, and initial Published Service settings safely.

Bootstrap secrets/tickets are treated as credentials and are not redisplayed through ordinary `show`.

## 6. Objects

List and inspect:

```text
show objects
show object <OBJECT>
show object <OBJECT> references
```

Create/edit static Object:

```text
set object <OBJECT> type host
set object <OBJECT> type network
set object <OBJECT> type fqdn

set object <OBJECT> value <VALUE>
set object <OBJECT> description <TEXT>
set object <OBJECT> name <NEW_NAME>
```

Remove value or Object:

```text
unset object <OBJECT> value <VALUE>
unset object <OBJECT> description
unset object <OBJECT>
```

Rules:

- `set object <OBJECT> type ...` creates the Object if absent.
- Static Object type changes after values/references exist should be rejected unless a safe explicit conversion workflow is implemented.
- An Object may hold multiple compatible values.
- Managed Endpoint is not a creatable `type` value.
- Referenced Objects cannot be deleted.
- Value mutations run policy-impact analysis.

## 7. Object Groups

```text
show object-groups
show object-group <GROUP>
show object-group <GROUP> references

set object-group <GROUP>
set object-group <GROUP> description <TEXT>
set object-group <GROUP> member <OBJECT_OR_GROUP>

unset object-group <GROUP> member <OBJECT_OR_GROUP>
unset object-group <GROUP>
```

Nested membership, if enabled, is cycle-checked.

A group containing members invalid for a selected policy field causes the whole assignment to fail. Members are not silently ignored.

## 8. Managed Endpoints

```text
show managed-endpoints
show managed-endpoint <ENDPOINT>
show managed-endpoint <ENDPOINT> addresses
show managed-endpoint <ENDPOINT> references
```

There is no normal public:

```text
set managed-endpoint ...
unset managed-endpoint ...
```

Creation/removal follows Client lifecycle.

An Orphaned endpoint remains queryable while referenced.

## 9. Published Services

```text
show published-services
show published-service <CLIENT_OR_ENDPOINT> <SERVICE>
```

Where local/client-side service mutation is supported:

```text
set published-service <SERVICE> type <ssh|http|https|tcp>
set published-service <SERVICE> target-mode <self|routed>
set published-service <SERVICE> target-host <HOST>
set published-service <SERVICE> target-port <PORT>
set published-service <SERVICE> enabled

unset published-service <SERVICE> enabled
unset published-service <SERVICE>
```

Semantics:

```text
SELF
  effective destination = Managed Endpoint
  local target may be 127.0.0.1 or another local address

ROUTED
  effective destination = configured reachable target host
  connector = Managed Endpoint
```

Changing target mode/host/port runs policy-impact analysis.

Public-port allocation/reservation remains server-controlled unless an explicit supported command says otherwise.

## 10. Service Presets

```text
show service-presets
show service-preset <PRESET>

set service-preset <PRESET>
set service-preset <PRESET> type <ssh|http|https|tcp>
set service-preset <PRESET> target-mode <self|routed>
set service-preset <PRESET> target-port <PORT>
set service-preset <PRESET> description <TEXT>

unset service-preset <PRESET>
```

A Service Preset is creation-time convenience only. It has no continuing ownership relation to services already created from it.

## 11. Remote Access rules

List and inspect:

```text
show remote-access
show remote-access <RULE>
show remote-access <RULE> impact
```

Create/edit:

```text
set remote-access <RULE>
set remote-access <RULE> source <OBJECT_OR_GROUP>
set remote-access <RULE> destination <OBJECT_OR_GROUP>
set remote-access <RULE> service <PROTOCOL> <PORT>
set remote-access <RULE> action <allow|deny>
set remote-access <RULE> description <TEXT>
set remote-access <RULE> enabled
```

Remove fields / rule:

```text
unset remote-access <RULE> source <OBJECT_OR_GROUP>
unset remote-access <RULE> destination <OBJECT_OR_GROUP>
unset remote-access <RULE> service <PROTOCOL> <PORT>
unset remote-access <RULE> enabled
unset remote-access <RULE>
```

Ordering:

```text
set remote-access <RULE> before <OTHER_RULE>
set remote-access <RULE> after <OTHER_RULE>
```

New rule default:

```text
status   = disabled
position = bottom
```

Evaluation:

```text
top-down
first complete match wins
explicit ALLOW / DENY
implicit final DENY
multiple selectors in one dimension = OR
Source AND Destination AND Service dimensions must all match
```

## 12. Remote Access test/explain

```text
test remote-access <SOURCE_IP> <DESTINATION> <PROTOCOL> <PORT>
```

Example:

```text
test remote-access 203.0.113.10 10.10.10.50 tcp 22
```

Output includes:

```text
source Object matches
destination Object matches
ordered rule trace
first complete match
effective ALLOW/DENY
Published Service match
connector/target availability
final effective access result
```

Unless explicitly documented as live, `test` is simulation/explanation and does not mutate state or establish the application connection.

## 13. Internet Access rules

```text
show internet-access
show internet-access <RULE>
show internet-access <RULE> impact

set internet-access <RULE>
set internet-access <RULE> source <OBJECT_OR_GROUP>
set internet-access <RULE> destination <OBJECT_OR_GROUP>
set internet-access <RULE> service <PROTOCOL> <PORT>
set internet-access <RULE> action <allow|deny>
set internet-access <RULE> description <TEXT>
set internet-access <RULE> enabled

unset internet-access <RULE> source <OBJECT_OR_GROUP>
unset internet-access <RULE> destination <OBJECT_OR_GROUP>
unset internet-access <RULE> service <PROTOCOL> <PORT>
unset internet-access <RULE> enabled
unset internet-access <RULE>

set internet-access <RULE> before <OTHER_RULE>
set internet-access <RULE> after <OTHER_RULE>
```

Internet Access uses its own order independent of Remote Access. Within a rule, multiple selectors in the same dimension are OR; Source AND Destination AND Service dimensions must all match.

Valid destination types include FQDN, public Host, public Network, and compatible Object Groups subject to security validation.

## 14. Internet Access test/explain

```text
test internet-access <SOURCE_IP> <DESTINATION> <PORT> <PROTOCOL>
```

Example:

```text
test internet-access 10.10.10.20 google.com 443 https
```

Output should include Object matches, DNS/security validation where applicable, ordered rule trace, and final action.

## 15. Fixed TCP

The canonical Fixed TCP grammar is implementation-frozen during the implementation phase, but it must use the same Object/policy authority rather than a separate flat destination authority.

Target discovery surface:

```text
show fixed-tcp
show fixed-tcp <ENTRY>
set fixed-tcp <ENTRY>
unset fixed-tcp <ENTRY>
```

Any direct mutation must reuse Internet Access policy validation and cannot bypass implicit default DENY.

## 16. AI Principals

```text
show ai-principals
show ai-principal <PRINCIPAL>
show ai-principal <PRINCIPAL> references

set ai-principal <PRINCIPAL>
set ai-principal <PRINCIPAL> description <TEXT>
set ai-principal <PRINCIPAL> enabled

unset ai-principal <PRINCIPAL> enabled
unset ai-principal <PRINCIPAL>
```

Creation is a guided/auth-aware workflow. Raw authentication credentials are not accepted or echoed through generic property commands unless the implementation defines a secure credential-ingest command with non-echo semantics.

Credential revocation/rotation is exposed through a dedicated safe workflow, for example:

```text
system credential revoke ai-principal <PRINCIPAL>
system credential rotate ai-principal <PRINCIPAL>
system credential configure ai-principal <PRINCIPAL> authentication static-bearer
system credential configure ai-principal <PRINCIPAL> authentication oauth
system credential configure ai-principal <PRINCIPAL> oauth-redirect <URI>
system credential approve-oauth <PENDING-ID> [AI-PRINCIPAL]
```

Authentication modes:

```text
Static Bearer    operator-issued token in Authorization: Bearer
OAuth            built-in OAuth 2.1 authorization server + resource server
                 (authorization_code+PKCE S256, refresh_token, client_credentials)
                 DCR (/oauth/register) and CIMD when the client presents an
                 https metadata URL as client_id
Auth model       static-bearer+built-in-oauth2.1-as/rs+rfc9728
```

`client_credentials` mints a separate expiring `drauth_` access token bound to
the canonical MCP resource. It is not an alias for Static Bearer.
Authorization-code exchanges also mint a rotating `drref_` refresh token.
DCR/CIMD consent requires `approve-oauth <PENDING-ID> <AI-PRINCIPAL>`.

Do not call Static Bearer "OAuth". Raw tokens are shown only at issuance.

## 16.1 Remote MCP connector (Claude / ChatGPT)

```text
MCP URL: https://<hostname>/mcp
```

1. Prefer `AUTO_ACME` public TLS (`set mcp-tls mode auto-acme`).
2. Create an AI Principal and AI Access rules for the intended hosts/tools.
3. Add the public `/mcp` URL as a custom connector / remote MCP server.
4. Complete OAuth (PKCE S256). Approve unbound DCR/CIMD requests with
   `system credential approve-oauth <PENDING-ID> <PRINCIPAL>`.
5. Tool discovery must be read-only; writes/exec remain AI Access gated.

`USER_CERTIFICATE` is for customer-managed publicly trusted certificates.
`PRIVATE_CA` is for internal clients that explicitly trust the private CA — not
the default ChatGPT/Claude cloud connector path.

Not every ChatGPT subscription supports full write MCP; treat write/exec
support as plan-dependent on the vendor side.

## 17. AI Access rules

```text
show ai-access
show ai-access <RULE>
show ai-access <RULE> impact

set ai-access <RULE>
set ai-access <RULE> principal <PRINCIPAL>
set ai-access <RULE> target endpoint <ENDPOINT>
set ai-access <RULE> target client-group <GROUP>
set ai-access <RULE> capability <CAPABILITY>
set ai-access <RULE> path <PATTERN>
set ai-access <RULE> exec-timeout <SECONDS>
set ai-access <RULE> action <allow|deny>
set ai-access <RULE> description <TEXT>
set ai-access <RULE> enabled
set ai-access <RULE> before <OTHER_RULE>
set ai-access <RULE> after <OTHER_RULE>

unset ai-access <RULE> target endpoint <ENDPOINT>
unset ai-access <RULE> target client-group <GROUP>
unset ai-access <RULE> capability <CAPABILITY>
unset ai-access <RULE> path <PATTERN>
unset ai-access <RULE> exec-timeout
unset ai-access <RULE> enabled
unset ai-access <RULE>
```

Initial capability names:

```text
list_hosts
get_host
get_system_info
exec
read_file
write_file
upload_file
download_file
list_processes
```

Unknown capability names fail closed.

AI Access evaluation is top-down first complete match, with explicit ALLOW/DENY and implicit final DENY. New rules are disabled at the bottom. Multiple targets/capabilities inside one rule are OR; Principal AND Target AND Capability AND applicable constraints must all match.

A rule intended to be truly read-only must not grant `exec`.

## 18. AI authorization test

```text
test ai-access <PRINCIPAL> <ENDPOINT> <CAPABILITY> [OPERAND]
```

Examples:

```text
test ai-access chatgpt-support dp1 read_file /var/log/vendor/app.log
test ai-access cursor-dev lab1 exec 'systemctl status vendor'
```

The test explains authorization only; it does not run the command or read the file.

## 19. AI activity

```text
show ai-activity
show ai-activity principal <PRINCIPAL>
show ai-activity endpoint <ENDPOINT>
```

Output is bounded and sanitized. It does not print secrets, full sensitive file contents, or unrestricted command output.

## 20. Policy timing

Canonical network rule:

```text
Policy changes apply immediately to new connections.
```

Established connections are not implicitly terminated by policy edits.

Canonical AI rule:

```text
Each new MCP tool invocation evaluates the current AI Access policy.
```

An already-running operation is not implicitly killed by a later policy edit.

## 21. Policy impact and confirmation

All security-relevant mutating commands use the same impact engine.

Interactive output may include:

```text
Access broadened: YES
Access narrowed: NO
Affected rules: 2
Newly shadowed: 1
Before: DENY
After: ALLOW via #10
Continue? [y/N]:
```

Broadening defaults to No.

Non-interactive automation requires an explicit acknowledgement mechanism implemented consistently across resources; silent bypass is not allowed.

## 22. Reference protection

Examples:

```text
unset object external1
```

must fail when referenced and list references.

Likewise for Object Groups, AI Principals, Client Groups, and other durable dependencies where deletion would silently alter security meaning.

## 23. Concurrency

Mutating interactive workflows use optimistic concurrency.

If the stored row version changed since the edit began, the mutation fails with no partial write.

## 24. System status

```text
show status
```

must include control-plane/runtime consistency when running on a server:

```text
Control DB       : Healthy
DB Revision      : 42
Remote Policy    : 42 active
Internet Policy  : 42 active
AI Policy        : 42 active

MCP Bridge
----------
Backend       : Healthy
Backend Bind  : 127.0.0.1:6103
Public URL    : https://<control-host>/mcp
Protocol      : 2026-07-28
Transport     : Streamable HTTP
Authentication: Static Bearer / OAuth
Auth Model    : static-bearer+built-in-oauth2.1-as/rs+rfc9728
```

Public URL is `Not configured` in Direct mode because there is no Data Relay Link HTTPS frontend on TCP/443. Remote MCP requires Enterprise single-443.

A mismatch is surfaced as warning/critical/error according to the canonical health model.

```text
system diagnostics mcp
```

reports backend health, loopback bind, public URL, frontend `/mcp` routing, and authentication modes. Backend Healthy does not imply remote MCP is healthy.

## 24.1 MCP Public TLS

Public cloud Remote MCP (ChatGPT / Claude connectors) needs a publicly trusted
certificate on `https://<hostname>/mcp`. Default mode is `AUTO_ACME`.

```text
set mcp-tls hostname mcp.example.com
set mcp-tls mode auto-acme
set mcp-tls contact-email ops@example.com
system certificate preflight
system certificate issue
show mcp-tls
system certificate renew
```

Modes:

```text
AUTO_ACME          publicly trusted certificate via ACME HTTP-01 (default for cloud MCP)
USER_CERTIFICATE   import an existing cert/key through system certificate import
PRIVATE_CA         DRLink private CA leaf for internal/test clients that trust the CA
```

`PRIVATE_CA` is not the default ChatGPT/Claude cloud connector path. Operators
do not need to run certbot/nginx/acme.sh directly.

## 25. Version

```text
show version
```

Canonical fields:

```text
Data Relay Link: <display identity>
Channel: <development|preview|stable>
Source HEAD: <40-character SHA>
Relay Engine (FRP): <version>
Control DB Schema: <schema version>
```

Stable identity requires an immutable matching tag and qualification evidence.

## 26. Audit

```text
system audit
system audit revision <REV>
system audit entity <TYPE> <ID>
system audit ai-principal <PRINCIPAL>
```

Audit output contains bounded metadata and impact summaries, not arbitrary sensitive payloads.

## 27. Revisions

```text
system revisions
system revision <REV>
system diff <REV_A> <REV_B>
```

Target rollback grammar:

```text
system rollback <REV>
```

Rollback is only public after it is implemented and qualified. It creates a new audited revision rather than rewriting history.

## 28. Backup / restore

```text
system backup <PATH>
system backup validate <PATH>
system restore <PATH>
```

Backup uses a consistent SQLite snapshot mechanism. It is not equivalent to copying the live DB file.

Restore validates archive, DB integrity, schema compatibility, ownership/modes, recompiles runtime artifacts, activates them, and verifies generation consistency.

## 29. Diagnostics

```text
system diagnostics
system diagnostics control-plane
system diagnostics runtime
```

The historical `doctor` direct alias may be retained as a discoverable convenience only if it maps to the same read-only diagnostics path:

```text
doctor
```

Diagnostics do not mutate state unless the command explicitly says it is a repair operation.

## 30. Updates

```text
system update product
system update engine
```

Product and Relay Engine versions are independent.

Stable update paths use immutable qualified release resources only.

## 31. Help

```text
help
help clients
help objects
help remote-access
help internet-access
help ai-access
help system
help workflows
help commands
```

`help commands` is the complete public command catalog.


## 32. Menu

```text
menu
```

opens the role-aware guided navigation defined by the CLI IA.

## 33. Exit

```text
exit
```

leaves the REPL. At shell level, command completion returns to the shell normally.

## 34. Completion contract

Tab completion must be:

```text
non-executing
context-aware
role-aware
field-type-aware
secret-safe
```

Completion candidates are drawn from authoritative DB identity, not stale derived runtime artifacts.

## 34.1 Configuration bundles

ConfigurationBundle operations preserve the stable direct roots; there is no top-level `apply` command.

```text
system export configuration --output <PATH>
test configuration <PATH|->
system diff configuration <PATH|->
system apply configuration <PATH|->
```

`-` means standard input and exists specifically so an AI-generated block can be pasted into an SSH terminal without first creating/uploading a file.

`test configuration` is non-mutating and performs schema/reference/security validation plus embedded expected-policy tests.

`system diff configuration` compares the validated Change Plan to current authoritative state.

`system apply configuration` performs validate → tests → diff → impact analysis → confirmation → optimistic-concurrency check → one authoritative transaction → revision/audit → compile/activate/verify. Confirmation defaults to No.

ConfigurationBundle semantics:

```text
omitted resource → unchanged
state: present   → idempotent create/update
state: absent    → explicit delete
same effective state → NO CHANGE
```

A bundle never contains/re-exports raw Zero-Touch tickets, installation credentials, OAuth/static bearer secrets, private keys, or client identity private material.

For simple requests, AI should output one canonical direct command. For dependent multi-resource requests, AI should output one copy/paste ConfigurationBundle. Both paths use the same Change Plan engine.

Existing-client local service/target changes that cannot be performed from the server report `CLIENT_ACTION_REQUIRED` rather than false success.

Zero-Touch bundle entries describe enrollment plans only. Ticket issuance is separate and server-bounded to max 10 per request and max 10 active unused, with unique single-use tickets, default 1-hour TTL, and maximum 24-hour TTL.

See `CONFIGURATION_BUNDLE.md` for the normative schema and safety contract.

## 35. Obsolete development-era grammar

The current product rejects obsolete development-era commands such as
`service-profile`, `internet-profile`, ACL/access-list roots, top-level
access/egress command trees, and `help legacy`.

Operators must use the canonical v2.4.0 grammar (`remote-access`,
`internet-access`, `published-service`, Objects, and the stable direct roots).
Silent compatibility translation is not part of the stable contract.

## 36. Error semantics

Security-relevant invalid operations fail closed with actionable messages.

Examples:

```text
Object type is not valid for Internet Access Destination.
No changes were applied.
```

```text
Cannot remove Object external1.
Referenced by remote-access partner-ssh and internet-access approved-web.
```

```text
Object changed while you were editing it.
No changes were applied.
```

```text
Rule is shadowed by earlier rule #10 allow-all.
Effective action remains ALLOW.
```

## 37. Stable CLI invariants

```text
DIRECT_ROOTS=show,set,unset,test,system,menu,help,exit

LEGACY_ACL_PRIMARY_RESOURCE=NO
SERVICE_PROFILE_PRIMARY_RESOURCE=NO
INTERNET_PROFILE_PRIMARY_RESOURCE=NO

OBJECT_PRIMARY_RESOURCE=YES
OBJECT_GROUP_PRIMARY_RESOURCE=YES
CLIENT_GROUP_PRIMARY_RESOURCE=YES
PUBLISHED_SERVICE_PRIMARY_RESOURCE=YES
SERVICE_PRESET_PRIMARY_RESOURCE=YES
REMOTE_ACCESS_PRIMARY_RESOURCE=YES
INTERNET_ACCESS_PRIMARY_RESOURCE=YES
AI_PRINCIPAL_PRIMARY_RESOURCE=YES
AI_ACCESS_PRIMARY_RESOURCE=YES

FIRST_MATCH_ORDERING=YES
IMPLICIT_DEFAULT_DENY=YES
POLICY_IMPACT_ANALYSIS=YES
REFERENCE_PROTECTION=YES
OPTIMISTIC_CONCURRENCY=YES
CONFIGURATION_BUNDLE=YES
CONFIGURATION_BUNDLE_SHARED_CHANGE_PLAN=YES
CONFIGURATION_BUNDLE_IDEMPOTENT=YES
CONFIGURATION_BUNDLE_EXPLICIT_DELETE_ONLY=YES
ZERO_TOUCH_MAX_PER_ISSUE=10
ZERO_TOUCH_MAX_ACTIVE_UNUSED=10
ZERO_TOUCH_SINGLE_USE=YES
```
