# Data Relay Link

**Secure Connectivity for Isolated Networks**

Data Relay Link relays only the connections that are actually needed instead of joining entire networks.

```text
Remote Access     outside → inside
Internet Access   inside → approved Internet destinations
AI Access         authorized AI/MCP principal → approved private endpoints
```

> **Development status:** The current v2.4.0 branch is in a pre-stable control-plane redesign. The canonical target architecture is documented, but the exact development HEAD may not yet implement every v2.4.0 target command or feature. Do not treat this branch as a stable release.

Current project version: **2.4.0**
Current pinned FRP version: **v0.71.0**
Prepared release — v2.4.0 (tag pending). The `v2.4.0/dist/bootstrap-server.sh` URL would 404 until the immutable tag exists.

## Architecture

v2.4.0 target:

```text
                    Data Relay Link
                          │
                 Embedded SQLite SSOT
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   Remote Access    Internet Access      AI Access
   inbound relay    controlled egress    MCP Bridge
```

Control-plane state:

```text
/var/lib/drlink/drlink.db
```

No external database service is required.

## Key model

```text
Objects / Object Groups
  reusable Host / Network / FQDN / Managed Endpoint identities

Managed Endpoint
  policy identity created from a Data Relay Link Client

Published Service
  SELF or ROUTED inbound service

Remote Access
  ordered top-down first-match ALLOW/DENY rules

Internet Access
  ordered top-down first-match ALLOW/DENY rules

AI Access
  AI Principal + target + capability/path/exec policy
```

All policy planes are implicit default DENY.

## Remote Access

Remote Access uses official pinned `fatedier/frp` as its relay engine. Data Relay Link does not fork FRP.

Effective inbound access requires:

```text
Rule Match
+
Enabled Published Service
+
Reachable connector/target
```

Published Service modes:

```text
SELF
  service belongs to the Managed Endpoint itself
  local target may be 127.0.0.1

ROUTED
  Managed Endpoint relays to another reachable host/service
  routed host does not need its own agent
```

## Internet Access

Protected hosts can use standard HTTP/HTTPS proxy settings. The gateway allows only explicitly authorized destinations/protocols/ports.

Security includes:

```text
default DENY
server-side DNS
DNS rebinding resistance
SSRF/private/local/metadata protection
safe CONNECT/SNI behavior
explicit public Host/CIDR policy where supported
Fixed TCP through the same authority
```

Technical capability name: **Controlled Egress**. Normal CLI/resource name: **Internet Access**.

## AI Access / MCP

MCP is included in the v2.4.0 architecture.

Public remote MCP is `https://<canonical-control-host>/mcp` through the
single-443 HTTPS frontend. The MCP backend stays on `127.0.0.1:6103`.

```text
MCP host (Cursor / Claude / ChatGPT are target examples)
    ↓ authenticated HTTPS / MCP 2026-07-28 Streamable HTTP
Data Relay Link public /mcp
    ↓ loopback
MCP Bridge 127.0.0.1:6103
    ↓ AI Access authorization
Managed Endpoint / Client Group
    ↓
private host
```

Support claims are evidence-based. Protocol and official SDK coverage do not
imply Cursor, Claude, or ChatGPT product support until those hosts are tested.

Modern 2026-07-28 is stateless: no `initialize`, no protocol `ping`, and no
`Mcp-Session-Id`. Authentication is
`static-bearer+built-in-oauth2.1-as/rs+rfc9728` with authorization_code+PKCE,
refresh tokens, DCR, and CIMD for remote connectors.

Connect with one URL: `https://<hostname>/mcp`. Prefer `AUTO_ACME` for
public-cloud connectors; use `USER_CERTIFICATE` for customer-managed public
trust, or `PRIVATE_CA` only for internal clients that trust the private CA.

No separate MCP server is required on every internal host.

Minimum target capabilities include:

```text
exec
read_file
write_file
upload_file
download_file
```

A true read-only AI role must have `exec` disabled.

## CLI

Guided server root:

```text
Clients
Objects
Remote Access
Internet Access
AI Access
System
Help
Exit
```

Direct roots:

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

```text
ssh -p <public-port> user@<public-hostname>

Connect a client with zero-touch:

```text
set client --one-line --ssh-user ubuntu
```

Interactive create-client still prompts `Client SSH user`. There is no default username.

Zero-touch `--one-line` does **not**:
- join entire networks
- skip enrollment authentication

Official server bootstrap (immutable tag path after the tag is published; until the v2.4.0 tag exists this URL would 404):

```text
https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.4.0/dist/bootstrap-server.sh
```

Development channel remains explicit opt-in:

```text
FRP_RELEASE_CHANNEL=dev
```

A legacy client on an older updater can use a one-time verified bridge; it cannot replace current upgrade policy.
```

The legacy pre-stable public resources `service-profile`, `internet-profile`, and ACL-centric grammar are not the v2.4.0 target contract.

## Example target commands

```text
show network-objects
show managed-hosts
show remote-services

show remote-access
set remote-access partner-ssh source external1
set remote-access partner-ssh destination internal1
set remote-access partner-ssh service tcp 22
set remote-access partner-ssh action allow
set remote-access partner-ssh enabled

test remote-access 203.0.113.10 10.10.10.50 tcp 22

show internet-access
set internet-access approved-web source internal1
set internet-access approved-web destination external2
set internet-access approved-web service https 443
set internet-access approved-web action allow
set internet-access approved-web enabled

test internet-access 10.10.10.20 google.com 443 https

show ai-identities
show ai-access
show ai-access-log
```

These are target v2.4.0 grammar; current development code may lag until implementation closure.

## Declarative configuration and AI copy/paste

v2.4.0 stable also targets a `ConfigurationBundle` input for dependent multi-resource changes. It is an idempotent change set against the SQLite-authoritative server state, not a second source of truth.

Canonical operations remain under existing CLI roots:

```text
system export configuration drlink.yaml
test configuration drlink.yaml
system diff configuration drlink.yaml
system apply configuration drlink.yaml
```

Standard input is supported so an AI can provide one safe SSH copy/paste block without requiring file upload. Simple AI-assisted work should still use one canonical public `drlink` command.

All paths share one Change Plan: validate → test → diff → impact → confirm → transactional commit → revision/audit → runtime activation. Bundles never carry raw Zero-Touch tickets or other secrets.

Zero-Touch issuance is separate from deployment intent: max 10 unique single-use tickets per request, max 10 active unused tickets, default 1-hour TTL, maximum 24-hour TTL.

See [`docs/CONFIGURATION_BUNDLE.md`](docs/CONFIGURATION_BUNDLE.md).

## Policy safety

Security-relevant mutations run:

```text
validation
→ reference resolution
→ shadow/conflict analysis
→ policy-impact analysis
→ broadening confirmation when required
→ optimistic-concurrency check
→ transactional commit + revision/audit
→ runtime compile/activate
```

Object/Group/Published Service edits can change effective policy and are analyzed just like Rule edits.

Canonical timing:

> **Policy changes apply immediately to new connections.**

For MCP, every new tool invocation evaluates current AI Access policy.

## Backup and restore

The control DB uses SQLite WAL mode. A live DB is backed up with SQLite Online Backup/equivalent consistent snapshot, not a naive file copy.

Restore validates schema/integrity and recompiles runtime policy from the DB.

## Version status

Current target:

```text
PROJECT_VERSION=2.4.0
RELEASE_CHANNEL=development
FRP_VERSION=0.71.0
```

There is no stable `v2.4.0` tag until exact-HEAD qualification is complete.

Pre-tag installers/bootstrap must use an immutable exact SHA or immutable candidate artifact, never a future nonexistent stable tag.

## Documentation

Public docs: https://link.datarelay.run

Start here:

- [`docs/PRODUCT_MASTER.md`](docs/PRODUCT_MASTER.md) — product-level decisions.
- [`docs/CONTROL_PLANE_ARCHITECTURE.md`](docs/CONTROL_PLANE_ARCHITECTURE.md) — technical SSOT.
- [`docs/Data Relay Link CLI Information Architecture.md`](docs/Data%20Relay%20Link%20CLI%20Information%20Architecture.md) — CLI UX.
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) — target direct grammar.
- [`docs/CONFIGURATION_BUNDLE.md`](docs/CONFIGURATION_BUNDLE.md) — declarative configuration, AI copy/paste, and bounded Zero-Touch contract.
- [`docs/CONTROLLED_EGRESS.md`](docs/CONTROLLED_EGRESS.md) — Internet Access behavior.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security boundaries.
- [`docs/VERSION_POLICY.md`](docs/VERSION_POLICY.md) — version/release rules.
- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) — final stable gate.

## Non-goals

v2.4.0 does not require:

```text
Web UI
external database server
central SaaS control plane
HA database cluster
hundreds/thousands-client orchestration
VPN/full network overlay
SASE/SWG/CASB/DLP
TLS inspection
automatic firewall/DNS management
```

## Release rule

Stable release requires two complete Real E2E passes on the same final exact HEAD, including the three access planes and applicable lifecycle/platform gates.

Any code/dependency change resets the pass counter.
