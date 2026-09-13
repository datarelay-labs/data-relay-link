# drlink command reference

`drlink` is the everyday operator CLI for **Data Relay Link**. It does not add
new backend behavior. Existing tools (`frp-clients`, `frp-client-set`,
`frp-create-client`, …) remain the implementation.

Product framing (see `docs/PRODUCT_MASTER.md` §2.2): **Data Relay** is the
family; this CLI operates **Secure Remote Access** (inbound) and
**Controlled Egress** (outbound) on a Data Relay Link server.

## Canonical grammar (current)

```text
<resource> <action> [target] [property] [value] [options]
```

Single source of truth: `lib/frp_cli_catalog.py`. Root help, resource help,
context `?`, Tab, guided menu, and suggestions are generated from that catalog.
Host role decides which resources appear. Dual-role hosts see the union.

### Historical / compatibility grammar

Older verb-first forms still run for scripts:

```text
<verb> <resource> [target] [property] [value]
```

See `help legacy`. Do not treat verb-first as the advertised current CLI.

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
`client list` prints CLIENT ID as the first identity column. Tab completes
CLIENT ID only. A unique label or unique hostname still works when typed by
hand. An SSH connection string such as `user@host:port` is not a selector.
An ambiguous prefix fails closed; use a longer CLIENT ID prefix.

`client unset` removes stored metadata only.

`client release <CLIENT-ID>` permanently removes the client registry record,
management identity, and **all** service reservations / public ports for that
client. It does not delete the remote host or uninstall local software.

`client release <CLIENT-ID> <SERVICE-ID>` releases only that one service
reservation; the client identity remains (management-only is valid).

`client revoke` blocks management trust and keeps every reservation.

Those three are never aliases of each other. There is no `delete client`.

---

## Everyday resource-first commands

```text
status
version
client list
client list --group <GROUP>
client show <ID>
client show <ID> services
client show <ID> tags
client show <ID> groups
group list
group show <GROUP>
enrollment list
server audit
server upstream
service list
client info

client set <ID> label <value>
client set <ID> note <value>
client set <ID> tag <key> <value>
server set public-hostname <fqdn>
server set bootstrap-hostname <fqdn>

enrollment create
zero-touch create
backup create
group create <name> [--description TEXT]
group set <GROUP> name|description <value>
group add-client <GROUP> <CLIENT>
group remove-client <GROUP> <CLIENT>
group delete <GROUP>

client revoke <ID>
client release <ID> [SERVICE-ID]
enrollment revoke <ID>

doctor
update project [--check]
update engine [--check]
support bundle
help
help workflows
help legacy
menu
```

Compatibility verb-first forms (`set client`, `create group`,
`add client … group`, `rename group`, …) remain available as hidden aliases;
prefer the resource-first forms above (`client list`, not legacy list verbs).

---

## Access Control

```text
access list
access create <name> [--description TEXT]
access add-source <list> --name <name> --source <ip|cidr> [--ttl 30m|1h|4h|1d] [--yes]
access remove-source <list> --source <ip|cidr|name|id> [--yes]
access replace-source <list> --source <sel> --name <name> --new-source <ip|cidr> [--ttl …] [--yes]
access show <list>
access delete <list> [--yes]
access assign <client> <service-id> <list>
access public <client> <service-id> [--yes]
access show-service <client> <service-id>
access test <client> <service-id> <source-ip>
access log <client> <service-id> [--limit N] [--allow|--deny]
access menu
```

Interactive `drlink` server menu includes Access Control. Empty ALLOWLIST
assignment is refused. Deleting a list that is still referenced is refused.
IP allowlisting is defense-in-depth; keep target authentication enabled.

## Controlled Egress

Agentless outbound HTTP/HTTPS forward proxy policy (separate from Access Control).
Default listen port **6102**. Destinations require `--protocol http|https`.

```text
egress status
egress list
egress show <PROFILE>
egress create <name> [--description TEXT]
egress set <PROFILE> name|description <VALUE>
egress add-source <PROFILE> <CIDR> [--name NAME]
egress add-destination <PROFILE> <FQDN> <PORT> --protocol http|https
egress remove-source <PROFILE> <SELECTOR> [--yes]
egress remove-destination <PROFILE> <SELECTOR> [--yes]
egress test <source-ip> <host> <port>   # policy + DNS only; no live connect
egress enable <PROFILE>
egress disable <PROFILE>
egress delete <PROFILE> [--yes]
egress export <PROFILE> [--output PATH]
egress import <PATH> [PROFILE]
egress diff <PROFILE> <PATH>
```

Safe workflow: create (disabled) → add-source → add-destination + protocol →
test → enable. See `docs/CONTROLLED_EGRESS.md`.

## update

```text
update project [--check]
update engine [--check]
```

`update` with no resource keeps the previous role default (client project
tools on a client; engine update on a server). Updater security is unchanged:
stable tag, verified SHA256SUMS, fail-closed, rollback, no re-enrollment, no
CA/token/port loss. FRP stays pinned at 0.71.0.

## Other

```text
doctor
support bundle
support bundle --output <path>
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

`support bundle` writes a sanitized read-only diagnostic archive
(`frp-support-<hostname>-<YYYYMMDDTHHMMSSZ>.tar.gz`). Private keys, tokens,
enrollment secrets, and auth material are omitted or redacted. It does not
restart services.

Root `?` lists resources. Detailed syntax is under `help` / `help <resource>`
or a context `?`. `menu` is the guided numbered interface using the same
catalog vocabulary.

---

## Compatibility cheat sheet (verb-first → resource-first)

| Older form | Prefer |
|---|---|
| `show clients` | `client list` |
| `show client <ID>` | `client show <ID>` |
| `show groups` | `group list` |
| `show egress-profiles` | `egress list` |
| `create egress-profile` | `egress create` |
| `set egress-profile … --name` | `egress set … name` |
| `add egress-profile … destination` | `egress add-destination … --protocol` |
| `create group` | `group create` |
| `add client <ID> group <G>` | `group add-client <G> <ID>` |
| `rename group` | `group set <G> name` |
| `frp-update` / `update frp` | `update engine` |
| `support-bundle` | `support bundle` |
