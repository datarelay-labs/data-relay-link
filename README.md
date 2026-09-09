# Data Relay Link

**Data Relay Labs / Data Relay — secure connectivity for isolated networks.**

Data Relay provides:

- **Secure Remote Access** (inbound) — lightweight, CLI-first Zero-Touch remote access on official FRP
- **Controlled Egress** (outbound) — agentless HTTP/HTTPS forward proxy for approved destinations only

Data Relay Link helps you securely reach servers behind NAT or firewalls **and** allow closed networks to reach only the Internet destinations they need — without a full VPN, RMM platform, SWG/SASE stack, or custom FRP fork.

- Official [`fatedier/frp`](https://github.com/fatedier/frp) only (inbound)
- Exact pinned/tested FRP version
- Zero-Touch and manual enrollment
- Immutable client identity
- Persistent public-port reservations
- SSH, HTTP, HTTPS passthrough, and Custom TCP
- Named Access Lists / temporary TTL / connection access log
- Agentless Controlled Egress profiles (FQDN + source CIDR, default DENY)
- Local and internal-LAN targets
- Linux, macOS, and Windows client support according to the validation matrix below
- One primary operator interface: `sudo drlink`

Controlled Egress guide: [`docs/CONTROLLED_EGRESS.md`](docs/CONTROLLED_EGRESS.md)  
Product direction: [`docs/DATA_RELAY_ROADMAP.md`](docs/DATA_RELAY_ROADMAP.md)  
Documentation: **https://frp.xdr.ooo**

---

## Current release — v2.3.0 FINAL AUDIT CLOSURE

| Item | Current |
| --- | --- |
| Data Relay Link | **v2.3.0** |
| Pinned upstream FRP | **v0.71.0** |
| Intended install source | immutable `v2.3.0` tag (recreate/move on final audit HEAD) |
| Default deployment mode | **Direct** |
| Optional enterprise mode | **single-443** |
| Intended scale | approximately **1–50 clients** |

Current project version: **2.3.0**
Current pinned FRP version: **v0.71.0**

`v2.2.1` and earlier tags remain immutable historical releases. This tree
prepares **v2.3.0 FINAL AUDIT CLOSURE** with FRP pinned at `0.71.0`. A
premature GitHub `v2.3.0` tag/release already exists; after this PR lands,
recreate or move that tag onto the final audit-closure HEAD before treating
field installs as final. Following mutable `main` is explicit opt-in only,
for example `FRP_RELEASE_CHANNEL=dev`.

On development builds, use release channel, source ref, and verified bundle SHA256 to identify the exact build.

---

## Canonical Product Master (historical v2.2.1 docs closure)

The post-**v2.2.1** documentation restoration phase
**`CANONICAL_PRODUCT_MASTER_RESTORE_V2_2_1_DOCS_CLOSURE`** completed with
**PASS**. That work restored [`docs/PRODUCT_MASTER.md`](docs/PRODUCT_MASTER.md)
without moving the immutable `v2.2.1` tag or changing runtime artifacts. It is
historical context only; current product version and platform claims are under
**v2.3.0 FINAL AUDIT CLOSURE** above.

---

## Supported client platforms — v2.3.0

Real-host validation and container/CI portability are deliberately reported separately.

| Platform | v2.3.0 validation claim |
| --- | --- |
| **Ubuntu 24 physical host** | **Real E2E validated** |
| **Rocky Linux 8.10** | **Real E2E validated** |
| **Rocky Linux 9.4** | **Real E2E validated** |
| **Amazon Linux 2023** | **Real E2E validated** |
| **macOS Apple Silicon** | **Real E2E validated** |
| **Windows 10 / PowerShell 5.1** | **Real E2E validated** |
| **Amazon Linux 2** | **Container / CI portability only** — no live-host Real E2E claim |
| **PowerShell 7** | **CI validated** — same-host Real E2E is claimed only where `pwsh` is actually installed |

Additional automated Linux portability coverage includes Ubuntu 22.04/24.04, Rocky Linux 8/9, AlmaLinux 9, Amazon Linux 2023, and Amazon Linux 2.

The Data Relay Link **server remains Linux-based**. macOS and Windows are client platforms; a Windows Data Relay Link server is not part of the current product scope.

### What the final Real E2E covered

Across applicable platforms, the v2.3.0 release path validated the actual product lifecycle, including:

- install and Zero-Touch enrollment
- persistent `CLIENT ID`
- service identity and public-port preservation
- real SSH connectivity
- real HTTP connectivity
- internal-LAN target publishing
- service lifecycle
- sync/reconcile
- reboot/autostart
- update preservation
- backup/restore
- Manual Group MVP
- Public Hostname behavior
- Access Control Pack
- Target Health Check
- Support Bundle
- Service Profiles

Amazon Linux 2 and PowerShell 7 remain intentionally narrower claims as shown in the table above.

See [`docs/RELEASE_VALIDATION.md`](docs/RELEASE_VALIDATION.md) and the full documentation at https://frp.xdr.ooo/reference/platforms.

---

## What problem does it solve?

A typical remote system looks like this:

```text
Internet
   |
Firewall / NAT
   |
Private network
   |
Server
```

Traditional support access often means requesting a VPN account, changing firewall/NAT rules, configuring a bastion, or deploying a separate remote-management product.

Data Relay Link lets the client initiate an outbound FRP tunnel to a server you control:

```text
                    Internet
                        |
              Data Relay Link Server
                  Public endpoint
                        |
                 outbound FRP tunnel
                        |
          +-------------+-------------+
          |             |             |
       Client A      Client B      Client C
      NAT/firewall  NAT/firewall  NAT/firewall
```

The client can publish services running locally or services on other LAN hosts that the client can reach.

---

## Core product principles

```text
CLI First
Zero-Touch First
Lightweight First
Fail Closed
Official FRP only
Pinned / Tested FRP
Immutable CLIENT ID
Persistent public-port reservation
Update preserves identity/services/ports
No accidental re-enrollment
```

This project is intentionally **not** a Web UI, database-backed RMM, Kubernetes platform, enterprise RBAC system, or hundreds/thousands-endpoint fleet orchestrator.

---

## Install the server

For normal field installation, use the immutable stable tag:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/xdr-labs/frp-auto-deploy/v2.3.0/dist/bootstrap-server.sh \
  | sudo bash
```

Then verify:

```bash
sudo drlink show version
sudo drlink show status
sudo drlink doctor
```

Data Relay Link does **not** automatically modify external firewall/NAT rules, cloud security groups, UFW, firewalld, iptables, or DNS-provider records.

---

## Deployment modes

There are two product deployment modes.

### Direct

Typical public ports:

```text
TCP/443        FRP control
TCP/6099       Enrollment / management HTTPS
TCP/6000-6098 Published services
```

A Direct server can use a public IP directly or sit behind an external firewall/DNAT device.

### Enterprise single-443

For environments that require control/enrollment on TCP/443:

```text
Public TCP/443
  +-- HTTPS enrollment / management
  +-- FRP control over WSS

Published services
  +-- TCP/6000-6098
```

Internal allocator/FRP backend ports remain local to the server.

NAT is a network topology, not a third deployment mode.

See [`docs/DEPLOYMENT_MODES.md`](docs/DEPLOYMENT_MODES.md).

---

## Enroll a client

### Zero-Touch

On the server:

```bash
sudo drlink
```

Then use the guided command:

```text
create zero-touch
```

Or create an explicit SSH profile:

```bash
sudo drlink create enrollment \
  --one-line \
  --ssh \
  --ssh-user admin \
  --label branch-a
```

The SSH account must already exist on the target system. There is **no default username**:
do not assume `ubuntu`, `root`, or any distro-specific account.

Interactive creation may prompt:

```text
Client SSH user: aella
SSH port [22]: 22
```

Zero-touch does **not**:

- create an OS user
- install or enable an SSH server
- set a password
- create or modify SSH keys / `authorized_keys`
- change `sshd_config`

When `bootstrap_hostname` is configured with an operator-owned public DNS/TLS/reverse-proxy endpoint, the Linux Short URL can look like:

```bash
curl -fsSL https://bootstrap.example.com/i/<opaque-ticket> | sudo bash
```

The full `/i/<ticket>` URL is a short-lived credential and should be handled as sensitive data.

### Windows Zero-Touch security rule

Production Windows bootstrap does **not** use `irm ... | iex`.

The required trust flow is:

```text
download bootstrap file
        ->
verify expected SHA256
        ->
powershell.exe -File
```

See [`docs/WINDOWS_CLIENT.md`](docs/WINDOWS_CLIENT.md).

---

## Publish services

A client can publish one or many TCP services.

### SSH only

```text
FRP Server:<assigned-port>
        ->
Client 127.0.0.1:22
```

Connect with the assigned public service port:

```bash
ssh -p <public-port> aella@203.0.113.10
```

### Multiple local services

```text
ssh        -> 127.0.0.1:22
web-admin  -> 127.0.0.1:443
```

### Internal LAN targets

```text
lan-ssh -> 10.10.20.30:22
lan-web -> 10.10.20.40:80
```

Supported service model:

- SSH
- HTTP
- HTTPS passthrough
- Custom TCP

HTTPS is TCP passthrough; Data Relay Link does not terminate the application's TLS session or manage the application certificate.

---

## `drlink` — primary management interface

Start the persistent operator CLI:

```bash
sudo drlink
```

Typical server operations:

```text
show status
show version
show clients
show client <CLIENT-ID>
show enrollments
show groups
show audit

create enrollment
create backup

set client <CLIENT-ID> label branch-a
set client <CLIENT-ID> tag site seoul

revoke client <CLIENT-ID>
release service <CLIENT-ID> <SERVICE-ID>
release client <CLIENT-ID>

doctor
update project --check
update frp --check
```

The canonical client identity is immutable `CLIENT ID`. Label, hostname, note, tags, and groups are metadata and do not replace identity.

Full CLI reference: [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md).

---

## Lifecycle semantics

These operations intentionally mean different things:

```text
disable   != release
revoke    != release
uninstall != release
update    != re-enrollment
```

| Operation | Identity | Public port |
| --- | --- | --- |
| disable service | kept | **reserved** |
| enable service | kept | **same port reused** |
| edit service | kept | **preserved** |
| revoke client | management blocked | **reserved** |
| release service | kept | **released for that service** |
| release client | removed | **released** |
| local client uninstall | server identity remains | **reserved** |
| normal update | preserved | **preserved** |

Normal project/FRP updates do not require re-enrollment and are designed to preserve client identity, services, and public-port reservations.

---

## Public Hostname / DNS

The authoritative model is:

```text
Public IP       = infrastructure/control endpoint
Public Hostname = optional user-facing alias for published services
```

For example:

```text
ssh -p 6000 admin@access.example.com
ssh -p 6000 admin@203.0.113.10
```

IP fallback is preserved. Data Relay Link does not automatically manage DNS-provider records, ACME/Let's Encrypt, external NAT, or application certificates.

---

## Manual Group MVP

v2.3.0 includes the lightweight Group model intended for a few to a few dozen clients:

- Manual Group CRUD
- immutable Group ID
- multiple group membership
- tags
- basic filters
- persistence
- audit
- backup/restore preservation

Dynamic Group, nested hierarchy, broad destructive fleet operations, canary rollout frameworks, and hundreds/thousands-client orchestration are not current core scope.

## Access Control Pack

Included in prepared `v2.3.0` (FINAL AUDIT CLOSURE):

- Named reusable Access Lists (IPv4/IPv6 CIDR)
- Service modes: `PUBLIC` (default) and `ALLOWLIST`
- Optional temporary sources with absolute expiry (`expires_at`)
- Bounded connection ALLOW/DENY log
- `drlink access ...` interactive menu and scriptable CLI
- FRP 0.71.0 NewUserConn plugin enforcement (loopback-only; fail-closed for ALLOWLIST)

IP allowlisting is defense-in-depth. Keep target authentication enabled.

---

## Security model

The management plane is designed to fail closed.

- HTTPS-only enrollment/management
- project private CA
- canonical DER SHA256 CA pin during first bootstrap
- persistent ECDSA P-256 client management identity
- signed requests
- timestamp and nonce replay protection
- high-entropy, TTL, single-use Zero-Touch tickets
- first-machine binding
- bootstrap secrets hashed at rest
- FRP tunnel credential separated from management identity
- no general TLS-verification bypass

Installer/release artifacts use SHA256 integrity verification. The project currently does not require a separate long-lived signing PKI for release operation.

See [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Backup, restore, and updates

```bash
sudo drlink create backup
sudo drlink restore backup <path>

sudo drlink update project --check
sudo drlink update project

sudo drlink show upstream
sudo drlink update frp --check
```

`show upstream` is informational. Data Relay Link does not automatically follow the newest upstream FRP release; it stays on the explicitly qualified pinned version.

Legacy clients that do not have persisted release identity fail closed on remote update. Use the **one-time verified bridge** documented in [`docs/FRP_UPGRADE.md`](docs/FRP_UPGRADE.md); do not guess or silently switch a legacy install to a release channel.

---

## Current limits

- TCP services only
- Server platform is Linux
- Amazon Linux 2 has portability/CI validation only in the current release qualification
- PowerShell 7 is CI validated; same-host Real E2E depends on `pwsh` being present
- some SELinux Enforcing, native ARM64 systemd, older OpenSSL/system-library, and unusual network-topology combinations remain separate validation gates
- no automatic cloud firewall/NAT/DNS/ACME management
- no automatic SSH account/password/key management
- project bootstrap scripts are checksummed; independent project artifact signing remains a known residual supply-chain improvement area
- intended for approximately 1–50 clients, not large-scale fleet orchestration

---

## Documentation

| Topic | Link |
| --- | --- |
| Full documentation | **https://frp.xdr.ooo** |
| Supported platforms | https://frp.xdr.ooo/reference/platforms |
| Quick Start | https://frp.xdr.ooo/getting-started/quickstart |
| CLI Reference | [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) |
| Deployment modes | [`docs/DEPLOYMENT_MODES.md`](docs/DEPLOYMENT_MODES.md) |
| Security | [`docs/SECURITY.md`](docs/SECURITY.md) |
| Release validation | [`docs/RELEASE_VALIDATION.md`](docs/RELEASE_VALIDATION.md) |
| FRP/project upgrade | [`docs/FRP_UPGRADE.md`](docs/FRP_UPGRADE.md) |
| Product Master | [`docs/PRODUCT_MASTER.md`](docs/PRODUCT_MASTER.md) |
| Changes by release | [`CHANGELOG.md`](CHANGELOG.md) |

---

## Product definition in one sentence

> Data Relay Link v2.3.0 is a lightweight, CLI-first, Zero-Touch deployment and operations layer over official pinned FRP 0.71.0 for securely connecting and managing roughly 1–50 NAT/firewall-behind Linux, macOS, and Windows clients while preserving immutable client identity, service identity, and public-port reservations without requiring a Web UI, database, or large-scale fleet orchestration.
