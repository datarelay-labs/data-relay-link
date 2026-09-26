# Data Relay Link — AI Identity, AI Access, and MCP

> **Status:** v2.4 development operator/developer guide
> **Authority:** Public CLI semantics come from the CLI/AI Master; security and transport boundaries come from `SECURITY.md`.

## 1. Model

```text
Authentication
→ establish verified AI Identity

AI Access
→ decide which destination and permission that identity may use

MCP Bridge
→ integration/transport layer
```

MCP does not create a separate public identity model.

## 2. AI Identity

Canonical public resource:

```text
AI Identity
```

Examples:

```text
chatgpt
claude
cursor-dev
custom-ai
```

A display name alone is not trusted identity.

Server CLI entry:

```text
set ai-identity <NAME>
```

Interactive AI uses OAuth Authorization Code verification where supported.

Automation/custom AI may use OAuth Client Credentials where supported.

The exact public MCP/OAuth endpoint design and host interoperability must remain consistent with `SECURITY.md` and exact-HEAD qualification evidence.

## 3. Permission Objects

Permission Objects contain reusable DRLink operation permissions such as:

```text
host-info
process-read
file-read
command-exec
file-write
file-upload
file-download
```

Permission Groups collect Permission Objects.

Example:

```text
set permission-object read-only permissions host-info,process-read,file-read
```

A true read-only role does not grant command execution.

## 4. AI Access Rule

Canonical fields:

```text
name
source      → AI Identity
destination → Network Object / Network Group
permission  → Permission Object / Permission Group
enabled
```

Example first rule:

```text
set ai-access claude-prod mode whitelist source claude destination production-servers permission read-only enabled
```

## 5. Policy semantics

AI Access uses the same public policy mode model:

```text
BLACKLIST
→ matching enabled Rule DENY
→ otherwise ALLOW

WHITELIST
→ matching enabled Rule ALLOW
→ otherwise DENY
```

Rules are not ordered and do not carry per-rule ALLOW/DENY actions.

AI authentication remains mandatory even when AI Access enforcement is disabled.

## 6. Test and audit

Test authorization without mutation:

```text
test ai-access source <AI_IDENTITY> destination <DESTINATION> permission <PERMISSION>
```

Audit views:

```text
show ai-access-log
show ai-access-log identity <IDENTITY>
show ai-access-log destination <DESTINATION>
show ai-access-log permission <PERMISSION>
```

Useful entries expose timestamp, AI Identity, destination, permission, and result. Sensitive file contents, bearer tokens, and unrestricted command output are not audit payloads.

## 7. MCP security boundary

The intended server-side flow is:

```text
MCP host
→ authenticated HTTPS public MCP endpoint
→ server-side MCP Bridge
→ authenticated AI Identity
→ current AI Access authorization
→ authenticated DRLink Agent management path
→ target OS permission boundary
```

Remote Services or exposed SSH are not prerequisites for an authorized MCP operation.

Every new privileged tool invocation is authorized against current policy.

## 8. File and command permissions

Direct file operations must enforce configured path scope after safe canonical path resolution.

Public v2.4 configuration binds those scopes on the AI Access rule:

```text
set ai-access allow-read ... permission read-only paths /var/lib/vendor/** enabled
```

ConfigurationBundle rules use the same `paths` list. Omit `paths` on edit to preserve existing scopes; export includes configured scopes so same-state reapply is NO CHANGE.

`test ai-access` accepts optional `path <PATH>` so public policy test agrees with MCP runtime authorization for in-scope and out-of-scope file operations. Without a path, file permissions do not report unconditional ALLOW.

When `permission` is a Permission Group, public `test ai-access` expands to atomic permissions, evaluates each member with the same path-aware rules, and aggregates ALLOW only when every atomic member allows. Mixed Permission Groups therefore cannot report a false scalar ALLOW.

Command execution is stronger than direct read/write permissions because a shell may modify system state. Grant `command-exec` only when the target OS identity and privilege boundary are appropriate.

Unknown or ungranted operations are denied.

## 9. Secrets

Do not expose or place in ConfigurationBundle/AI copy-paste output:

```text
OAuth access/refresh tokens
Static Bearer tokens
private keys
enrollment tickets
credentials
```

Support bundles and logs must redact protected values.

## 10. Interoperability qualification

Do not claim ChatGPT, Claude, Cursor, or another MCP host as supported solely from protocol conformance.

Release qualification must retain real interoperability evidence for every host explicitly claimed as supported.
