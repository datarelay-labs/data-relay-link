# FRP Auto Deploy

**Lightweight, CLI-first, Zero-Touch remote access management on top of official FRP.**

FRP Auto Deploy helps you securely reach servers and services behind NAT or firewalls without building a full VPN, RMM platform, or custom FRP fork.

- Official [`fatedier/frp`](https://github.com/fatedier/frp) only
- Exact pinned/tested FRP version
- Zero-Touch and manual enrollment
- Immutable client identity
- Persistent public-port reservations
- SSH, HTTP, HTTPS passthrough, and Custom TCP
- Named Access Lists / temporary TTL / connection access log (main feature; not yet in published stable)
- Local and internal-LAN targets
- Linux, macOS, and Windows client support according to the validation matrix below
- One primary operator interface: `sudo frpctl`

Documentation: **https://frp.xdr.ooo**

---

## Current stable release

| Item | Current |
| --- | --- |
| FRP Auto Deploy | **v2.2.1** |
| Pinned upstream FRP | **v0.71.0** |
| Stable install source | immutable `v2.2.1` tag |
| Qualified candidate | `2140be5b6342c3651c16a458f8ea1bc9b577d992` |
| Release commit | `19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f` |
| Release qualification | **Double Full Real E2E PASS / PASS** on the same exact candidate HEAD |
| Candidate/release tree | **tree-identical** |
| Default deployment mode | **Direct** |
| Optional enterprise mode | **single-443** |
| Intended scale | approximately **1–50 clients** |

Current project version: **2.2.1**
Current pinned FRP version: **v0.71.0**

`v2.2.0` remains an immutable historical release. `v2.2.1` is the **current stable release** and keeps FRP pinned at `0.71.0`. Stable field installs use the immutable `v2.2.1` tag. Following mutable `main` is explicit opt-in only, for example `FRP_RELEASE_CHANNEL=dev`.

On development builds, use release channel, source ref, and verified bundle SHA256 to identify the exact build.

---

## Canonical Product Master / documentation closure

The post-release documentation restoration phase **`CANONICAL_PRODUCT_MASTER_RESTORE_V2_2_1_DOCS_CLOSURE`** completed with **PASS**.

| Closure item | Result |
| --- | --- |
| Start HEAD / v2.2.1 release commit | `19d4b6fb8a9bee2d477ace6f5c3ed70310e7ea8f` |
| Final `main` HEAD after canonical docs merge | `343f292d91d01c3f263ff5c443f101d185b5527f` |
| v2.2.1 tag target changed | **NO** |
| v2.2.0 tag changed | **NO** |
| New release created | **NO** |
| Product runtime files changed | **NO** |
| `dist/` changed | **NO** |
| Real E2E rerun | **NO — not required for docs-only closure** |
| Owner authoritative Master available | **YES** |
| Owner Master backup | **PASS** |
| Canonical Product Master restore | **PASS** |
| Product Master structural check | **PASS** |
| Current release data updated | **YES** |
| Platform matrix updated | **YES** |
| Release history preserved | **YES** |
| Provenance added | **YES** |
| Known corruption removed | **YES** |
| `BLOCKED_MISSING_AUTHORITATIVE_MASTER` removed | **YES** |
| Public metadata scan | **PASS** |
| Secret scan | **PASS** |
| `SHA256SUMS` updated | **YES** |
| README stale release state fixed | **YES** |
| Security stale release state fixed | **YES** |
| Root `GITHUB_SETUP.md` release URLs | **YES — already points at immutable `v2.2.1`**; no `docs/GITHUB_SETUP.md` exists |
| Owner manual E2E required | **NO** |
| Final documentation state | **CANONICAL** |

The damaged session-start / old GitHub `docs/PRODUCT_MASTER.md` copies matched at **2,173 lines** with SHA256 `67329d74f58276d75f3b140baf135fb09fc097899de60a192bcafd4f63743709`. Through **PR #12**, that truncated derivative was replaced by the Owner-reconstructed, full integrated Product Master (approximately **3,625 lines**), with release history preserved and provenance added. The incomplete surgical PR #13 was closed as superseded.

The canonical source is now [`docs/PRODUCT_MASTER.md`](docs/PRODUCT_MASTER.md). The documentation-only merge advanced repository `main` to `343f292…` but did **not** move the immutable `v2.2.1` tag, create a new release, or change runtime artifacts. Therefore the stable release identity remains **v2.2.1 / release commit `19d4b6f…` / FRP 0.71.0**.

---

## Supported client platforms — v2.2.1

Real-host validation and container/CI portability are deliberately reported separately.

| Platform | v2.2.1 validation claim |
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

The FRP Auto Deploy **server remains Linux-based**. macOS and Windows are client platforms; a Windows FRP Auto Deploy server is not part of the current product scope.

### What the final Real E2E covered

Across applicable platforms, the v2.2.1 release path validated the actual product lifecycle, including:

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

FRP Auto Deploy instead lets the client initiate an outbound FRP tunnel to a server you control:

```text
                    Internet
                        |
              FRP Auto Deploy Server
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
  https://raw.githubusercontent.com/datarelay-labs/frp-auto-deploy/v2.2.1/dist/bootstrap-server.sh \
  | sudo bash
```

Then verify:

```bash
sudo frpctl show version
sudo frpctl show status
sudo frpctl doctor
```

FRP Auto Deploy does **not** automatically modify external firewall/NAT rules, cloud security groups, UFW, firewalld, iptables, or DNS-provider records.

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
sudo frpctl
```

Then use the guided command:

```text
create zero-touch
```

Or create an explicit SSH profile:

```bash
sudo frpctl create enrollment \
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

HTTPS is TCP passthrough; FRP Auto Deploy does not terminate the application's TLS session or manage the application certificate.

---

## `frpctl` — primary management interface

Start the persistent operator CLI:

```bash
sudo frpctl
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

IP fallback is preserved. FRP Auto Deploy does not automatically manage DNS-provider records, ACME/Let's Encrypt, external NAT, or application certificates.

---

## Manual Group MVP

v2.2.1 includes the lightweight Group model intended for a few to a few dozen clients:

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

On current feature work (not yet published in immutable `v2.2.1`):

- Named reusable Access Lists (IPv4/IPv6 CIDR)
- Service modes: `PUBLIC` (default) and `ALLOWLIST`
- Optional temporary sources with absolute expiry (`expires_at`)
- Bounded connection ALLOW/DENY log
- `frpctl access ...` interactive menu and scriptable CLI
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
sudo frpctl create backup
sudo frpctl restore backup <path>

sudo frpctl update project --check
sudo frpctl update project

sudo frpctl show upstream
sudo frpctl update frp --check
```

`show upstream` is informational. FRP Auto Deploy does not automatically follow the newest upstream FRP release; it stays on the explicitly qualified pinned version.

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

> FRP Auto Deploy v2.2.1 is a lightweight, CLI-first, Zero-Touch deployment and operations layer over official pinned FRP 0.71.0 for securely connecting and managing roughly 1–50 NAT/firewall-behind Linux, macOS, and Windows clients while preserving immutable client identity, service identity, and public-port reservations without requiring a Web UI, database, or large-scale fleet orchestration.
