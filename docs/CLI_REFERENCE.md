# drlink command reference

`drlink` is the everyday operator CLI for **Data Relay Link**. It does not add
new backend behavior. Existing tools (`frp-clients`, `frp-client-set`,
`frp-create-client`, …) remain the implementation.

Product framing (see `docs/PRODUCT_MASTER.md` §2.2): **Data Relay** is the
family; this CLI operates **Secure Remote Access** (inbound) and
**Controlled Egress** (outbound) on a Data Relay Link server.

Interactive root navigation uses beginner domains (**Clients**, **Services**,
**Internet Access**, **System**). Those labels are not the same as the
capability names above. See `docs/PRODUCT_MASTER.md` §18.0.

## Canonical grammar (current)

Public roots:

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

Typical form:

```text
<action> <resource> [target] [value]
```

Single source of truth: `lib/frp_cli_final_commands.json` via
`lib/frp_cli_catalog.py` (`PUBLIC_COMMANDS` / `COMMANDS`). Root help,
resource help, context `?`, Tab, guided menu (`NAVIGATION_TREE`), and
suggestions are generated from that catalog. Host role decides which
resources appear. Dual-role hosts use the server product-domain root.

### Historical / compatibility grammar

Older resource-first forms still run for scripts as hidden compatibility:

```text
<verb> <resource> [target] [property] [value]
```

See `help legacy`. Do not treat resource-first as the advertised current CLI.

Interactive keys:

```text
Tab   = immediately show/complete what can be entered here
?     = detailed contextual explanation
Enter = execute
↑/↓   = session history
```

Tab completes a unique match inline. When several next tokens remain, the
first Tab prints the candidate list above the prompt and restores the exact
input line for editing. A second Tab on the same unchanged line does not
reprint the list. Tab never runs the command and never clears the screen.
Type `?` (then Enter) for detailed context help when needed.

`↑` / `↓` walk this session only. History is never written to disk
(`~/.bash_history`, `~/.drlink_history`, or `HISTFILE`).

The canonical client selector is **CLIENT ID**: the immutable short machine
identity (usually 8 hex characters; longer when that prefix is not unique).
Changing label, note, tags, or hostname never changes CLIENT ID.
`show clients` prints CLIENT ID as the first identity column. Tab completes
CLIENT ID only. A unique label or unique hostname still works when typed by
hand. An SSH connection string such as `user@host:port` is not a selector.
An ambiguous prefix fails closed; use a longer CLIENT ID prefix.

Client removal model (three distinct operations):

```text
unset client <CLIENT> trust
  Block management trust. Registry record and public ports stay reserved.

unset client <CLIENT> service <SERVICE>
  Release one service reservation / public port. Client identity stays.

unset client <CLIENT>
  Remove the client registry record, management identity, and all
  service reservations / public ports. Does not delete the remote host
  or uninstall Data Relay Link on the remote machine.
```

Metadata helpers remain separate:

```text
unset client <CLIENT> label
unset client <CLIENT> note
unset client <CLIENT> tag <KEY>
unset client <CLIENT> group <GROUP>
```

Those forms are never aliases of each other. There is no public
`unset client <CLIENT> <SERVICE>` shorthand and no `delete client`.


## Everyday canonical commands

```text
show status
system version
show clients
show client <CLIENT>
show client <CLIENT> services
show client <CLIENT> tags
show client <CLIENT> groups
show groups
show group <GROUP>
show enrollments
system audit
system update check-engine
show services
system info

set client
set client <CLIENT> label <value>
set client <CLIENT> note <value>
set client <CLIENT> tag <key> <value>
set client <CLIENT> group <GROUP>
set server public-hostname <fqdn>
set server bootstrap-hostname <fqdn>
set server installer-url <url>
set server windows-installer-url <url>

set enrollment
set enrollment bulk
system backup
system support-bundle
set group <GROUP>
set service-profile <PROFILE>
set internet-profile <PROFILE>
set access-rule <RULE>

set access-source <RULE> <SOURCE>
set service-access <CLIENT> <SERVICE> <RULE>
set internet-source <PROFILE> <CIDR>
set internet-destination <PROFILE> <FQDN> <PORT> <PROTOCOL>
set fixed-tcp <ENTRY>
set internet-profile <PROFILE> enabled
set fixed-tcp <ENTRY> enabled

unset client <CLIENT> trust
unset client <CLIENT> service <SERVICE>
unset client <CLIENT>
unset client <CLIENT> group <GROUP>
unset enrollment <ENROLLMENT>
unset group <GROUP>
unset service-profile <PROFILE>
unset access-rule <RULE>
unset access-source <RULE> <SELECTOR>
unset service-access <CLIENT> <SERVICE>
unset internet-source <PROFILE> <SELECTOR>
unset internet-destination <PROFILE> <FQDN> <PORT> [PROTOCOL]
unset internet-profile <PROFILE> enabled
unset internet-profile <PROFILE>
unset fixed-tcp <ENTRY> enabled
unset fixed-tcp <ENTRY>

system restore <path>
system update product
system update engine
system update check-engine
test access <CLIENT> <SERVICE> <SOURCE-IP>
test internet <SOURCE-IP> <HOST> <PORT> [PROTOCOL]
test fixed-tcp <ENTRY> <SOURCE-IP>
system diagnostics
system export internet-profile <PROFILE> [PATH]
system import internet-profile <FILE> [PROFILE]
system diff internet-profile <PROFILE> <FILE>
```

Public UX does not advertise GNU-style `--options`. Complex create flows
use guided prompts. Backend tools may still use flags internally.

Session helpers:

```text
help
help clients
help services
help internet
help system
help commands
help workflows
help legacy
menu
system history
system clear
exit
```

Enrollment lifetime is collected by guided prompts (or hidden automation
paths). An enrollment credential is a short-lived hand-off, so the ceiling is
deliberately far below the `enrollment_retention_days` maximum; larger values
are rejected rather than silently clamped.

Compatibility forms remain available as hidden aliases; prefer the
canonical forms above (`show clients`, not legacy list verbs).


## Access Rules

Beginner/operator term and direct CLI resource: **Access Rules**
(`access-rule` / `access-rules`).

```text
show access-rules
show access-rule <RULE>
set access-rule <RULE>
set access-source <RULE> <SOURCE>
set service-access <CLIENT> <SERVICE> <RULE>
unset access-source <RULE> <SELECTOR>
unset service-access <CLIENT> <SERVICE>
unset access-rule <RULE>
test access <CLIENT> <SERVICE> <SOURCE-IP>
show access-log
```

Interactive `drlink` server menu places Access Rules under **Services**.
Empty allowlist assignment is refused. Deleting a rule that is still
referenced is refused. IP allowlisting is defense-in-depth; keep target
authentication enabled.

## Internet Access (Controlled Egress)

Beginner/operator navigation term: **Internet Access**.
Capability / architecture term: **Controlled Egress**.

```text
show internet
show internet-profiles
show internet-profile <PROFILE>
set internet-profile <PROFILE>
set internet-profile <PROFILE> name|description <VALUE>
set internet-source <PROFILE> <CIDR>
set internet-destination <PROFILE> <FQDN> <PORT> <PROTOCOL>
test internet <SOURCE-IP> <HOST> <PORT> [PROTOCOL]
set internet-profile <PROFILE> enabled
unset internet-profile <PROFILE> enabled
system import internet-profile <FILE> [PROFILE]
system export internet-profile <PROFILE> [PATH]
system diff internet-profile <PROFILE> <FILE>
show fixed-tcp
show fixed-tcp <ENTRY>
set fixed-tcp <ENTRY>
set fixed-tcp <ENTRY> enabled
unset fixed-tcp <ENTRY> enabled
unset fixed-tcp <ENTRY>
test fixed-tcp <ENTRY> <SOURCE-IP>
show internet-templates
show internet-template <TEMPLATE>
set internet-profile <NEW_PROFILE> template <TEMPLATE>
```

`test internet` evaluates policy + DNS. It is **not** a live destination
connection test (menu label: **Check policy**).

Safe workflow: create profile (disabled) → set source → set destination +
protocol → check policy → enable. See `docs/CONTROLLED_EGRESS.md`.

## Updates

Public update commands:

```text
system update product
system update engine
system update check-engine
```

Updater security is unchanged: stable tag, verified SHA256SUMS, fail-closed,
rollback, no re-enrollment, no CA/token/port loss. Relay Engine (FRP) stays
pinned at the explicitly qualified version.

## Other

```text
system diagnostics
system support-bundle
system history
system clear
help
help commands
help workflows
help legacy
?
menu
exit
```

`system support-bundle` writes a sanitized read-only diagnostic archive
(`frp-support-<hostname>-<YYYYMMDDTHHMMSSZ>.tar.gz`). Private keys, tokens,
enrollment secrets, and auth material are omitted or redacted. It does not
restart services.

Three discovery surfaces (do not conflate them):

```text
?     = executable root / next-token discovery
help  = conceptual / domain help (and help commands)
menu  = guided numbered UI (Clients / Services / Internet Access / System)
```

Bare `?` lists executable roots: `show set unset test system menu help exit`.
Full expert grammar is under `help commands`.


## Compatibility cheat sheet (legacy → canonical)

| Older / legacy form | Prefer |
|---|---|
| `client list` | `show clients` |
| `enrollment list` | `show enrollments` |
| `enrollment revoke` | `unset enrollment` |
| `egress list` | `show internet-profiles` |
| `egress create` | `set internet-profile` |
| `egress status` | `show internet` |
| `access list` | `show access-rules` |
| `access assign` | `set service-access` |
| `frp-update` / `update frp` | `system update engine` |
| `support-bundle` | `system support-bundle` |
| `purge enrollment` / `delete enrollment` | `unset enrollment` |
