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
1) Clients
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
help clients | objects | remote-access | internet-access | ai-access | system | workflows | commands
<command> ?
Tab
```

ConfigurationBundle / MCP TLS live under **System** help and `system ?` / `show ?` / `set ?` — not as separate top-level menu domains.

---

## Public MCP prerequisites (do before Section I)

Current lab server public IP (as of readiness assessment):

```text
PUBLIC_IP=221.139.249.113
SSH_ALIAS=frp-e2e-server
```

Rick must prepare a **project-controlled hostname** for real public MCP TLS:

```text
PUBLIC_MCP_REQUIRED_HOSTNAME=<choose, e.g. mcp.<your-domain>>
PUBLIC_MCP_REQUIRED_DNS=A/AAAA -> 221.139.249.113 (or current server public IP)
PUBLIC_MCP_REQUIRED_PORTS=TCP/80 (HTTP-01), TCP/443 (HTTPS /mcp)
```

Notes from readiness probe:

```text
fw.xdr.ooo        -> 221.139.249.110 (NOT this server; do not reuse blindly)
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
| frp-e2e-rocky9-rescue | Rocky 9 | | | | rescue host; use only if appropriate |
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
  Menu matches Clients/Objects/Remote Access/Internet Access/AI Access/System
  No help legacy advertisement
  No traceback
PASS/FAIL=
Finding=
```

---

# SECTION B — Zero-Touch

Prefer discovery via `menu → Clients → Connect a new client` or `set client`.

### TEST B1 — Issue one ticket (default TTL)

```text
TEST ID=B1
Objective=Issue one Zero-Touch ticket; default TTL; one-time secret display
Exact public command / operator action=
  set client
  (follow prompts: Zero-Touch path)
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
  show clients
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
  Managed Endpoint created
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

### TEST E1 — Object CRUD

```text
TEST ID=E1
Objective=Host/Network/FQDN objects create/show/edit/delete protection
Exact public command / operator action=
  set object <NAME> type host|network|fqdn
  set object <NAME> value <VALUE>
  show objects
  show object <NAME>
  (rename/edit if allowed)
  unset object <NAME>
Expected result=No silent cascade; in-use delete protected with clear error
PASS/FAIL=
Finding=
```

### TEST E2 — Object Group / Client Group

```text
TEST ID=E2
Objective=Membership, nested group, cycle rejection
Exact public command / operator action=
  set object-group <NAME>
  set client-group <NAME>
  add members via guided/set forms
  attempt cycle
Expected result=Cycle rejected; membership visible; delete protection when referenced
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
  set object ... / set internet-access ... action allow
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
  Change/delete disposable Objects/policies/Published Services/MCP TLS non-secret state/Zero-Touch non-secret lifecycle state
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
  verify autostart, identity, Published Services, policies, MCP TLS, ACME timer
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
