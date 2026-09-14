# drlink command reference

`drlink` is the everyday operator CLI for **Data Relay Link**. It does not add
new backend behavior. Existing tools (`frp-clients`, `frp-client-set`,
`frp-create-client`, …) remain the implementation.

Product framing (see `docs/PRODUCT_MASTER.md` §2.2): **Data Relay** is the
family; this CLI operates **Secure Remote Access** (inbound) and
**Controlled Egress** (outbound) on a Data Relay Link server.

## Canonical grammar (current)

```text
<action> <resource> [target] [value]
```

Single source of truth: `lib/frp_cli_catalog.py`. Root help, resource help,
context `?`, Tab, guided menu, and suggestions are generated from that catalog.
Host role decides which resources appear. Dual-role hosts see the union.

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

`release client <CLIENT-ID>` permanently removes the client registry record,
management identity, and **all** service reservations / public ports for that
client. It does not delete the remote host or uninstall local software.

`release client <CLIENT-ID> <SERVICE-ID>` releases only that one service
reservation; the client identity remains (management-only is valid).

`revoke client` blocks management trust and keeps every reservation.

Those three are never aliases of each other. There is no `delete client`.


## Everyday action-first commands

```text
show status
show version
show clients
show client <ID>
show client <ID> services
show client <ID> tags
show client <ID> groups
show groups
show group <GROUP>
show enrollments
show audit
show upstream
show services
show info

set client <ID> label <value>
set client <ID> note <value>
set client <ID> tag <key> <value>
set server public-hostname <fqdn>
set server bootstrap-hostname <fqdn>

create zero-touch
create enrollment
create backup
create support-bundle
create group <name>
create service-profile <name>
create egress-profile <name>
create access-list <name>

add client <CLIENT> group <GROUP>
remove client <CLIENT> group <GROUP>
add egress-destination <PROFILE>
add egress-source <PROFILE>
add access-source <LIST>

enable egress-profile <PROFILE>
disable egress-profile <PROFILE>

revoke client <ID>
revoke enrollment <ID>
release client <ID>
release service <ID> <SERVICE-ID>
delete enrollment <ID>
delete group <GROUP>
delete service-profile <PROFILE>
delete egress-profile <PROFILE>
delete access-list <LIST>

restore backup <path>
update product
update engine
test access
test egress
doctor
```

Public UX does not advertise GNU-style `--options`. Complex create/add flows
use guided prompts. Backend tools may still use flags internally.

Session helpers:

```text
help
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

Compatibility verb-first forms (`set client`, `create group`,
`add client … group`, `rename group`, …) remain available as hidden aliases;
prefer the action-first forms above (`show clients`, not legacy list verbs).


## Access Control

```text
access list
access show <list>
access assign <client> <service-id> <list>
access show-service <client> <service-id>
access test <client> <service-id> <source-ip>
access menu
```

characters and rejects control characters, newlines, and ANSI escapes.

Interactive `drlink` server menu includes Access Control. Empty ALLOWLIST
assignment is refused. Deleting a list that is still referenced is refused.
IP allowlisting is defense-in-depth; keep target authentication enabled.

## Controlled Egress

Agentless outbound HTTP/HTTPS forward proxy policy (separate from Access Control).

```text
egress status
egress list
egress show <PROFILE>
egress set <PROFILE> name|description <VALUE>
egress add-destination <PROFILE> <FQDN> <PORT> --protocol http|https
egress test <source-ip> <host> <port>   # policy + DNS only; no live connect
egress enable <PROFILE>
egress disable <PROFILE>
egress import <PATH> [PROFILE]
egress diff <PROFILE> <PATH>
```

Safe workflow: create (disabled) → add-source → add-destination + protocol →
test → enable. See `docs/CONTROLLED_EGRESS.md`.

## update

```text
```

`update` with no resource keeps the previous role default (client project
tools on a client; engine update on a server). Updater security is unchanged:
stable tag, verified SHA256SUMS, fail-closed, rollback, no re-enrollment, no
CA/token/port loss. FRP stays pinned at 0.71.0.

## Other

```text
doctor
create support-bundle
create support-bundle --output <path>
help
help <resource>
help workflows
help legacy
?
menu
history
clear
exit
```

`create support-bundle` writes a sanitized read-only diagnostic archive
(`frp-support-<hostname>-<YYYYMMDDTHHMMSSZ>.tar.gz`). Private keys, tokens,
enrollment secrets, and auth material are omitted or redacted. It does not
restart services.

Root `?` lists resources. Detailed syntax is under `help` / `help <resource>`
or a context `?`. `menu` is the guided numbered interface using the same
catalog vocabulary.


## Compatibility cheat sheet (verb-first → action-first)

| Older form | Prefer |
|---|---|
| `show clients` | `show clients` |
| `show client <ID>` | `show client <ID>` |
| `show groups` | `show groups` |
| `show egress-profiles` | `egress list` |
| `create egress-profile` | `egress create` |
| `set egress-profile … --name` | `egress set … name` |
| `add egress-profile … destination` | `egress add-destination … --protocol` |
| `create group` | `create group` |
| `add client <ID> group <G>` | `group add-client <G> <ID>` |
| `rename group` | `group set <G> name` |
| `frp-update` / `update frp` | `update engine` |
| `support-bundle` | `create support-bundle` |
