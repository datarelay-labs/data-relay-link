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

```text
<action> <resource> [target] [value]
```

Single source of truth: `lib/frp_cli_catalog.py` (`COMMANDS`). Root help,
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

`unset client` removes stored metadata only.

`unset client <CLIENT-ID>` permanently removes the client registry record,
management identity, and **all** service reservations / public ports for that
client. It does not delete the remote host or uninstall local software.

`unset client <CLIENT-ID> <SERVICE-ID>` releases only that one service
reservation; the client identity remains (zero published services is valid
for an already enrolled client).

`unset client <CLIENT> trust` blocks management trust and keeps every reservation.

Those three are never aliases of each other. There is no `delete client`.


## Everyday canonical commands

```text
show status
system version
show clients
show client <ID>
show client <ID> services
show client <ID> tags
show client <ID> groups
show groups
show group <GROUP>
show enrollments
system audit
system update check-engine
show services
system info

set client <ID> label <value>
set client <ID> note <value>
set client <ID> tag <key> <value>
set server public-hostname <fqdn>
set server bootstrap-hostname <fqdn>

set client
set enrollment
system backup
system support-bundle
set group <name>
create service-profile <name>
set internet-profile <name>
set access-rule <name>

add client <CLIENT> group <GROUP>
remove client <CLIENT> group <GROUP>
add egress-destination <PROFILE>
add egress-source <PROFILE>
add access-source <LIST>

enable egress-profile <PROFILE>
disable egress-profile <PROFILE>

unset client <ID>
unset enrollment <ID>
unset client <ID>
unset client <ID> <SERVICE-ID>
unset enrollment <ID>
unset group <GROUP>
delete service-profile <PROFILE>
delete egress-profile <PROFILE>
delete access-list <LIST>

system restore <path>
system update product
system update engine
test access
test internet
system diagnostics
```

Public UX does not advertise GNU-style `--options`. Complex create/add flows
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
history
clear
exit
```

Enrollment lifetime is collected by guided prompts (or hidden automation
paths). An enrollment credential is a short-lived hand-off, so the ceiling is
deliberately far below the `enrollment_retention_days` maximum; larger values
are rejected rather than silently clamped.

Compatibility forms remain available as hidden aliases; prefer the
canonical forms above (`show clients`, not legacy list verbs).


## Access Rules

Beginner/operator term: **Access Rules**. Direct command resource remains
`access-list`.

```text
show access-rules
set access-rule <name>
show access-rule <list>
add access-source <list>
remove access-source <list>
set access-assign <client> <service-id> <list>
set access-public <client> <service-id>
test access <client> <service-id> <source-ip>
show access-log
```

Interactive `drlink` server menu places Access Rules under **Services**.
Empty ALLOWLIST assignment is refused. Deleting a list that is still
referenced is refused. IP allowlisting is defense-in-depth; keep target
authentication enabled.

## Internet Access (Controlled Egress)

Beginner/operator navigation term: **Internet Access**.
Capability / architecture term: **Controlled Egress**.

```text
show internet
show internet-profiles
set internet-profile <NAME>
show internet-profile <PROFILE>
set egress-profile <PROFILE> name|description <VALUE>
add egress-destination <PROFILE>
add egress-source <PROFILE>
test internet
enable egress-profile <PROFILE>
disable egress-profile <PROFILE>
import egress <PATH>
diff egress <PROFILE> <PATH>
show fixed-tcp
set fixed-tcp <NAME>
show internet-templates
set internet-profile <NEW> template <NAME>
```

`test internet` evaluates policy + DNS. It is **not** a live destination
connection test (menu label: **Check policy**).

Safe workflow: create (disabled) → add-source → add-destination + protocol →
check policy → enable. See `docs/CONTROLLED_EGRESS.md`.

## update

`update` with no resource keeps the previous role default (client project
tools on a client; engine update on a server). Updater security is unchanged:
stable tag, verified SHA256SUMS, fail-closed, rollback, no re-enrollment, no
CA/token/port loss. FRP stays pinned at 0.71.0.

## Other

```text
system diagnostics
system support-bundle
help
help commands
help workflows
help legacy
?
menu
history
clear
exit
```

`system support-bundle` writes a sanitized read-only diagnostic archive
(`frp-support-<hostname>-<YYYYMMDDTHHMMSSZ>.tar.gz`). Private keys, tokens,
enrollment secrets, and auth material are omitted or redacted. It does not
restart services.

Root `?` and bare `help` show product work areas (Clients / Services /
Internet Access / System). Full expert grammar is under `help commands`.
`menu` is the guided numbered interface using the navigation tree.


## Compatibility cheat sheet (legacy → canonical)

| Older / legacy form | Prefer |
|---|---|
| `client list` | `show clients` |
| `enrollment list` | `show enrollments` |
| `enrollment revoke` | `unset enrollment` |
| `egress list` | `show internet-profiles` |
| `egress create` | `set internet-profile` |
| `egress status` | `show egress` |
| `access list` | `show access-rules` |
| `access assign` | `set access-assign` |
| `frp-update` / `update frp` | `system update engine` |
| `support-bundle` | `system support-bundle` |
| `purge enrollment` | `delete enrollment` |
