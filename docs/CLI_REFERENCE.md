# frpctl command reference

`frpctl` is the everyday operator CLI. It does not add new backend behavior.
Existing tools (`frp-clients`, `frp-client-set`, `frp-create-client`, …) remain
the implementation.

Grammar:

```text
<verb> <resource> [target] [property] [value]
```

Host role decides which commands appear in Tab and help. Dual-role hosts see
the union. There is no `server …` / `client …` top-level namespace.

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
(`~/.bash_history`, `~/.frpctl_history`, or `HISTFILE`).

The canonical client selector is **CLIENT ID**: the immutable short machine
identity (usually 8 hex characters; longer when that prefix is not unique).
Changing label, note, tags, or hostname never changes CLIENT ID.
`show clients` prints CLIENT ID as the first identity column. Tab completes
CLIENT ID only. A unique label or unique hostname still works when typed by
hand. An SSH connection string such as `user@host:port` is not a selector.
An ambiguous prefix fails closed; use a longer CLIENT ID prefix.

`unset` removes stored metadata. `release` returns public port reservations.
`revoke` removes management identity. Those three are never aliases of each
other. There is no `delete client`.

---

## show

```text
show status
show version
show clients
show clients --group <GROUP>
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
```

`status` and `version` remain shortcuts for `show status` / `show version`.
Canonical help prefers the `show` form.

`show clients` reuses the existing client table. The identity columns are
CLIENT ID, LABEL, and HOSTNAME. `show client <ID>` is the overview.
`show client <ID> services` and `show client <ID> tags` print only that view.

`show enrollments` lists every issued enrollment credential that is still on
disk: manual Enrollment Code records and zero-touch bootstrap tickets. Secrets
are never printed. Zero-touch issuance that creates both an enrollment file and
a bootstrap ticket appears once (ticket ID). Lifecycle states are normalized to
`pending`, `bound`, `completed`, `expired`, or `revoked`. Terminal records
(`expired`, `completed`, `revoked`) are retained for
`enrollment_retention_days` (default 30) and then removed automatically during
enrollment issuance or allocator startup. Use `revoke enrollment <ID>` for active
(`pending`/`bound`) credentials and `purge enrollment <ID>` for terminal records.

## set

Server:

```text
set client <ID> label <value>
set client <ID> note <value>
set client <ID> tag <key> <value>
set installer-url <url>
set server hostname <fqdn>
set server bootstrap-hostname <fqdn>
```

`set server hostname` configures an optional DNS alias for published-service
access. It does not change FRP control (`frp_server` / `serverAddr`), CLIENT ID,
public ports, or the CA. DNS records are managed outside FRP Auto Deploy.

`set server bootstrap-hostname` configures the optional publicly trusted
Zero-Touch short URL hostname. FRP Auto Deploy does not create DNS records,
issue certificates, or configure ACME. See `docs/ZERO_TOUCH_SHORT_URL.md`.

The backend still accepts `--tag key=value`. The parser converts
`tag <key> <value>` to that form. Quoted values work
(`tag location "OCI Osaka"`). The older `tag key=value` token is still
accepted.

Client:

```text
set service <service-id> target-host <host>
set service <service-id> target-port <port>
set service <service-id> ssh-user <user>
set service <service-id> name <value>
set service <service-id> health-type <tcp|http|disabled>
set service <service-id> health-timeout <seconds>
set service <service-id> health-interval <seconds>
set service <service-id> health-max-failed <count>
set service <service-id> health-path </path>
```

Service IDs are immutable. Pending service edits become live only after
`apply`. Disable/enable reuse the same public port. Client-side disable does
not release the server reservation. Health checks are disabled by default;
when enabled, FRP `healthCheck` settings are written into `frpc.toml`.
`show services` / `status` report CLIENT / TUNNEL / TARGET separately.

## unset

```text
unset client <ID> label
unset client <ID> note
unset client <ID> tag <key>
unset server hostname
unset server bootstrap-hostname
```

Removes administrator metadata only (or the optional public / bootstrap
hostname). Display label falls back to hostname. Does not change identity,
machine-id, ports, or enrollment. Unsetting the public hostname falls back to
Public IP access. Unsetting the bootstrap hostname falls back to `zt1` Zero-Touch
commands.

## create / add

```text
create group <name> [--description TEXT]
add client <CLIENT> group <GROUP>
create zero-touch
create enrollment [--one-line] [--ssh --ssh-user USER --label NAME]
create enrollments --count N
create enrollments --csv clients.csv
create backup [path]
add service [--preset ssh|http|https|custom] ...
```

Manual groups have immutable IDs (`grp_` plus eight lowercase hex digits),
mutable names and descriptions, and multiple client memberships. Group
selectors resolve in this order: exact ID, unique ID prefix, unique exact
name. `all` and `ungrouped` are reserved virtual selectors, not stored group
objects.

```text
rename group <GROUP> <name>
set group <GROUP> name <name>
set group <GROUP> description <text>
delete group <GROUP>
remove client <CLIENT> group <GROUP>
```

Deleting a group removes its membership references but does not change client
identity, services, or ports. Enrollment-time group assignment is deferred.

`create zero-touch` is the recommended everyday client onboarding path.
Enrollment Code and bootstrap ticket secrets are never completed or shown by
`show` / `?` / Tab.

## enable / disable / apply / discard

```text
enable service <service-id>
disable service <service-id>
apply
discard
```

Client-local pending changes. `apply` does not release server ports.

## revoke / purge / release / restore

```text
revoke client <ID>
revoke enrollment <ID>
purge enrollment <ID>
purge enrollments --older-than <days>
release service <ID> <service-id>
release client <ID>
restore backup <path>
```

`revoke enrollment` prevents a pending or bound enrollment credential from being
used. It does not apply to terminal records (`expired`, `completed`, `revoked`).

`purge enrollment` permanently removes terminal enrollment metadata. Active
pending or bound enrollments must be revoked first. Bulk purge matches terminal
records whose terminal timestamp is older than the requested threshold.
Non-interactive purge requires `FRP_ENROLLMENT_PURGE_YES=yes`.

Terminal enrollment JSON retention and audit log retention are separate.
Purging enrollment metadata does not delete audit events.

`release` keeps the existing confirmation, locking, and passive port recheck.
`restore` keeps archive validation, snapshot, restart, doctor, and rollback.

## access (server)

Named reusable Service Access Lists, optional TTL entries, and recent
connection authorization history. Access is keyed by CLIENT ID + Service ID
(not by public port). Modes are `PUBLIC` (default for existing services) and
`ALLOWLIST`.

```text
access
access list
access create <name> [--description TEXT]
access add-source <list> --name <name> --source <ip|cidr> [--ttl 30m|1h|4h|1d]
access remove-source <list> --source <ip|cidr|name|id>
access show <list>
access delete <list>
access assign <client> <service-id> <list>
access public <client> <service-id>
access show-service <client> <service-id>
access test <client> <service-id> <source-ip>
access log <client> <service-id> [--limit N] [--allow|--deny]
```

Interactive `frpctl` server menu includes Access Control. Empty ALLOWLIST
assignment is refused. Deleting a list that is still referenced is refused.
IP allowlisting is defense-in-depth; keep target authentication enabled.

## update

```text
update project [--check]
update frp [--check]
```

`update` with no resource keeps the previous role default (client project
tools on a client; `frp-update` on a server). Updater security is unchanged:
stable tag, verified SHA256SUMS, fail-closed, rollback, no re-enrollment, no
CA/token/port loss. FRP stays pinned at 0.71.0.

## Other

```text
doctor
help
help show
help set client
help legacy
?
show ?
set client <ID> ?
menu
history
clear
exit
```

Root `?` lists verbs only. Detailed syntax is under `help` / `help <verb>`
or a context `?`. `menu` is the guided numbered interface using the same
vocabulary (Show / Set / Unset / Create / Update / Revoke / Release).

---

## Compatibility aliases

These still work for scripts and muscle memory. Tab and canonical help hide
them. `help legacy` lists them.

| Alias | Canonical |
| --- | --- |
| `clients` | `show clients` |
| `client` / `client-info` | `show client` |
| `client-set` / `edit-client` | `set client` / `unset client` |
| `enroll` / `create-client` | `create enrollment` |
| `enroll-bulk` | `create enrollments` |
| `enrollments` | `show enrollments` |
| `enrollment-revoke` | `revoke enrollment` |
| `revoke` / `revoke-client` | `revoke client` |
| `release-service` | `release service` |
| `release-client` | `release client` |
| `project-update` / `client-update` | `update project` |
| `frp-update` / `server-update` | `update frp` |
| `backup` | `create backup` |
| `restore PATH` | `restore backup PATH` |
| `upstream` | `show upstream` |
| `audit` | `show audit` |
| `services` / `manage` / `info` | `show services` / `add`+`set service` / `show info` |
| `status` / `version` | `show status` / `show version` |

Direct `/usr/local/sbin/frp-*` tools are unchanged.
