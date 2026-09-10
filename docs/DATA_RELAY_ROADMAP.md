# Data Relay — Product Direction & Roadmap

> **Document role:** Product Direction + Scope + Architecture Principles + Development Roadmap
> **Status:** Implementation in progress on `feature/data-relay-controlled-egress`
> **Product identity:** **Data Relay**
> **Legacy technical identity:** Data Relay Link
> **Primary interface:** `sudo drlink` (until a separate naming migration is explicitly approved)
> **Design principle:** **Do not connect entire networks. Relay only the connections that are actually needed.**
> **Operator guide:** `docs/CONTROLLED_EGRESS.md`

---

# 1. Why the Product Direction Changes

Data Relay Link started as a lightweight deployment and operations layer for official `fatedier/frp`.

Its original problem was primarily **outside → inside** connectivity:

```text
Internet / Support Engineer
        ↓
FRP Server
        ↓
FRP Client
        ↓
Private / Closed Network Service
```

The product has since evolved beyond simple FRP installation. It already manages enrollment, identity, services, access control, lifecycle, audit, backup/restore, diagnostics, groups/tags, and multi-platform clients.

The next product problem is the opposite direction:

```text
Closed / Restricted Network
        ↓
Only approved Internet destinations
        ↓
Internet
```

Many closed or restricted networks block general outbound Internet access but still require limited connectivity for:

- OS and security updates
- package repositories
- license servers
- vendor APIs
- SaaS integrations
- telemetry or required cloud APIs

Today this is commonly solved with firewall rules, Squid or another forward proxy, VPN/network changes, or custom per-environment configuration. These approaches work, but are often operationally heavy for environments that only need a small number of explicitly approved connections.

Therefore the product direction expands from **FRP deployment automation** to **secure bidirectional connection relay for isolated and restricted networks**.

---

# 2. Product Identity

## 2.1 Product Name

**Data Relay**

`Data Relay Link` becomes a legacy/technical identity rather than the full product definition.

FRP remains an important transport engine for inbound remote access, but it is no longer the product identity itself.

```text
Data Relay
    │
    ├── Secure Remote Access
    │       └── powered by official FRP
    │
    └── Controlled Egress
            └── built-in agentless HTTP/HTTPS forward proxy
```

The existing repository/package/CLI names do **not** need to be renamed immediately. A broad source-code rename should be a separate controlled migration after the new product direction is implemented and validated.

---

# 3. Product Definition

Data Relay is:

> **A lightweight secure connectivity gateway for isolated and restricted networks, providing controlled inbound remote access and agentless outbound Internet access.**

In simpler user-facing language:

> **필요한 연결만 안전하게 열어주는 폐쇄망/제한망용 경량 연결 게이트웨이**

The product solves two related problems with one server and one operational model.

### Inbound — Secure Remote Access

```text
Outside Administrator / Service
            ↓
        Data Relay
            ↓
Approved internal service only
```

Examples:

- SSH
- HTTP / HTTPS
- RDP or custom TCP services where supported by the transport model
- APIs
- LAN targets reachable through a managed FRP client/gateway

### Outbound — Agentless Controlled Egress

```text
Closed Network Host
       ↓
HTTP / HTTPS Proxy Setting
       ↓
Data Relay Egress Gateway
       ↓
Approved destination only
```

Examples:

- `security.ubuntu.com:443`
- package repositories
- license servers
- GitHub/vendor APIs
- approved SaaS endpoints

Everything not explicitly allowed is denied.

---

# 4. Core Product Philosophy

The common security principle for both directions is:

> **Do not connect networks. Relay only the connections that are needed.**

Traditional network access often grants broad connectivity:

```text
VPN
Network routing
Broad firewall allow rules
General Internet access
```

Data Relay instead grants individual required connections:

```text
Inbound:
Internet → approved internal service

Outbound:
Internal host → approved Internet destination
```

The product must remain:

- simple to deploy
- simple to understand
- safe to operate
- lightweight by design
- CLI first
- suitable for a few systems to a few dozen systems/sites

It must **not** become a general VPN, SASE, Secure Web Gateway, RMM, large fleet platform, or enterprise web-security stack.

---

# 5. Target Environments

Primary target environments include:

- closed networks
- restricted outbound networks
- network-separated environments
- public-sector / financial environments with strict network policy
- manufacturing / OT environments
- security appliances
- customer/partner environments requiring temporary or persistent support access
- systems where direct Internet access is prohibited but selected external services are required
- environments where firewall rules are difficult to maintain because destinations are FQDN/CDN based rather than stable IP addresses

Typical operational examples:

### Security Update

```text
Internal Server
   ↓
Data Relay
   ↓
security.vendor.com:443   ALLOW
all other destinations    DENY
```

### License / API

```text
Security Appliance
   ↓
Data Relay
   ↓
license.vendor.com:443    ALLOW
api.vendor.com:443        ALLOW
Internet:any              DENY
```

### Remote Technical Support

```text
Support Engineer
   ↓
Data Relay
   ↓
SSH / Web / API on approved internal targets
```

---

# 6. Product Architecture

```text
                         INTERNET

        Administrator                  Approved Services
             │                         Update / Repo / API
             │                                ▲
             ▼                                │
     ┌────────────────────────────────────────────┐
     │                Data Relay                  │
     │                                            │
     │  Secure Remote Access   Controlled Egress │
     │  Access Control         Egress Control    │
     │  Service Management     FQDN/Port ACL     │
     │  Audit                  DNS/SSRF Guard    │
     │  Doctor                 Audit             │
     └───────────┬────────────────────▲───────────┘
                 │                    │
═════════════════╪════════════════════╪══════════════════
                 │      FIREWALL      │
                 │                    │
          CLOSED / RESTRICTED NETWORK
                 │                    │
         FRP Client/Gateway     Agentless Hosts
                 │                    │
          Internal Services      Proxy setting only
```

Important architectural distinction:

- **Inbound Remote Access uses official FRP.**
- **Outbound Controlled Egress does not need FRP on the protected host.**
- Controlled Egress is a server-side Data Relay capability.
- FRP must not be forced into the outbound path when a standard forward proxy is sufficient.

---

# 7. Secure Remote Access — Existing Product Pillar

The existing inbound capability remains a first-class product function.

Core principles remain unchanged:

- official FRP only; no FRP fork
- pinned/tested FRP versions
- zero-touch enrollment
- persistent client identity
- multiple services per client
- LAN target support
- service lifecycle management
- public port reservation/persistence
- access control
- audit
- doctor
- backup/restore
- simple group/tag/filter management
- no automatic customer firewall/NAT modification

Inbound access is intended for:

- administration
- technical support
- operational access
- selected published services

The product must expose only explicitly configured services, not entire internal networks.

---

# 8. Controlled Egress — New Product Pillar

## 8.1 Primary Requirement

Controlled Egress must work **without installing Data Relay/FRP client software on the protected host**.

The expected client-side configuration is only a standard proxy setting, for example:

```text
HTTP_PROXY=http://datarelay.example.com:6080
HTTPS_PROXY=http://datarelay.example.com:6080
```

The protected application/server then uses standard HTTP proxy behavior and HTTPS `CONNECT` tunneling.

For HTTPS destination traffic:

```text
Application
    ↓
CONNECT approved.example.com:443
    ↓
Data Relay
    ↓
Policy check
    ↓
TLS remains end-to-end between application and destination
```

Data Relay v1 does **not** decrypt application TLS.

---

# 9. Controlled Egress v1 — Required Features

## 9.1 HTTP Forward Proxy

Support standard HTTP proxy clients.

## 9.2 HTTPS CONNECT

Support standard `CONNECT host:port` behavior so existing applications can use `HTTPS_PROXY` without TLS interception.

## 9.3 Source Network ACL

Allow administrators to define which source IPs/CIDRs may use the egress service.

Example:

```text
10.10.20.0/24
203.0.113.10/32
```

This is the primary v1 authorization mechanism for agentless clients.

## 9.4 Destination FQDN Allowlist

Allow exact approved FQDN destinations.

Example:

```text
security.ubuntu.com:443
api.vendor.com:443
license.vendor.com:443
```

## 9.5 Controlled Subdomain Matching

Support carefully defined subdomain rules where operationally required.

Example:

```text
*.githubusercontent.com:443
```

Wildcard behavior must be narrow and explicit. Arbitrary pattern matching is not required.

## 9.6 Destination Port ACL

Destination permission is a combination of hostname and port.

```text
example.com:443   ALLOW
example.com:22    DENY
```

Default CONNECT port should be 443 unless another port is explicitly permitted.

## 9.7 Default Deny / Fail Closed

If policy state is missing, invalid, corrupt, or cannot be safely evaluated:

```text
DENY
```

must be the default behavior.

## 9.8 Audit

Record connection-level audit information such as:

- timestamp
- source address
- requested destination hostname
- destination port
- allow/deny decision
- matched policy/profile
- failure reason where safe

Do not log credentials, application payloads, sensitive URL query strings, or TLS contents.

## 9.9 Health / Doctor

`frpctl doctor` or an equivalent egress-specific doctor path should verify:

- gateway service state
- policy readability
- listening socket
- DNS resolution capability
- outbound connectivity test where explicitly requested
- dangerous configuration conditions

## 9.10 Backup / Restore

Egress policy state must participate in existing backup/restore lifecycle.

---

# 10. Egress Profile Model

A single SaaS/update service often requires multiple FQDNs. Therefore policy should be grouped as reusable **Egress Profiles**.

Example:

```text
Profile: ubuntu-update

Destinations:
  security.ubuntu.com:443
  archive.ubuntu.com:443

Sources:
  customer-a-network

Default:
  DENY
```

Another example:

```text
Profile: vendor-license

Destinations:
  license.vendor.com:443
  api.vendor.com:443
```

Initial product scope should support **user-defined profiles**.

A large vendor-maintained destination catalog is not required for v1.

---

# 11. Proposed CLI Experience

The CLI should remain simple and consistent with the existing `frpctl` operational model.

Illustrative UX:

```text
drlink> create egress-profile ubuntu-update
drlink> add egress-profile ubuntu-update destination security.ubuntu.com 443
drlink> add egress-profile ubuntu-update destination archive.ubuntu.com 443
drlink> add egress-profile ubuntu-update source 203.0.113.10/32

drlink> show egress-profiles
drlink> show egress-profile ubuntu-update
drlink> disable egress-profile ubuntu-update
drlink> enable egress-profile ubuntu-update
drlink> delete egress-profile ubuntu-update
```

Exact grammar should follow the canonical parser and existing CLI conventions after implementation audit.

The CLI must prefer understandable objects and lifecycle operations over exposing raw proxy configuration syntax.

---

# 12. Security Requirements

Controlled Egress is a security boundary, not merely a convenience proxy.

## 12.1 Server-Side DNS Resolution

The gateway resolves destination FQDNs on the server side.

## 12.2 DNS / SSRF Protection

After hostname resolution, every candidate destination IP must be validated before connection.

By default, reject destinations resolving to ranges such as:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
IPv6 loopback/link-local/private ranges
multicast/reserved ranges
cloud metadata addresses
```

The exact deny set should use maintained standard-library/network primitives rather than fragile string rules.

## 12.3 DNS Rebinding Resistance

Policy evaluation and actual connection must not perform unrelated independent DNS resolutions that permit validation of one IP and connection to another.

The gateway should connect to the exact validated resolution result or otherwise provide equivalent rebinding-safe behavior.

## 12.4 IP Literal Policy

Direct IP-literal destinations should be denied by default unless there is an explicit product requirement and safe policy model.

The primary product value is FQDN-based control.

## 12.5 Resource Protection

Implement reasonable:

- connection timeout
- idle timeout
- maximum concurrent connections
- request/header size limits
- defensive parsing
- rate/concurrency protection where necessary

The gateway must never become an open proxy.

---

# 13. Agentless Identity Limitation

Because Controlled Egress v1 requires **no agent**, the server normally identifies the caller by source network address.

If multiple hosts are behind the same NAT:

```text
Host A ─┐
Host B ─┼→ NAT public IP → Data Relay
Host C ─┘
```

Data Relay sees the same source address for all of them.

Therefore v1 must clearly distinguish:

> **Site/Network Policy** from **Per-Host Identity**.

Source CIDR policy is sufficient for many restricted-network use cases, but it cannot securely distinguish individual hosts behind the same NAT.

This is an accepted v1 limitation, not a bug.

---

# 14. Explicitly Excluded from Controlled Egress v1

The following are **not** part of v1:

- TLS Proxy endpoint
- mTLS client identity
- TLS interception / SSL bump
- certificate/root-CA deployment for traffic inspection
- URL path/content filtering
- web category filtering
- DLP
- malware scanning/sandboxing
- CASB
- browser isolation
- transparent proxying
- full L3 routing
- VPN functionality
- general Secure Web Gateway / SASE functionality
- automatic firewall changes
- automatic DNS changes

Because TLS Proxy endpoint is excluded, v1 should **not** depend on plaintext proxy username/password credentials as the primary security boundary across untrusted networks. Source IP/CIDR restriction remains the default v1 access control for the agentless proxy endpoint.

---

# 15. Optional / Later Capabilities

These may be considered only after real field demand.

## 15.1 Fixed TCP Egress

For proxy-unaware applications that need a fixed `host:port` destination:

```text
Internal Application
    ↓
Data Relay:published-port
    ↓
approved.vendor.com:custom-port
```

This must remain destination-pinned and policy-controlled.

For HTTPS applications, hostname/certificate behavior must be validated because connecting to a relay hostname instead of the original destination hostname can cause TLS hostname validation failure.

## 15.2 SOCKS5

Deferred until a real requirement exists.

## 15.3 PAC File

Deferred. Useful for workstation/browser environments but not required for initial server-focused use cases.

## 15.4 Strong Per-Host Agentless Identity

Deferred until a secure transport/authentication design is explicitly approved.

mTLS is currently excluded.

---

# 16. Network Responsibility Boundary

Data Relay does **not** automatically modify customer firewalls, NAT, DNS, routing, UFW, iptables, nftables, cloud security groups, or proxy settings.

For Controlled Egress, the customer/network administrator remains responsible for allowing the protected network to reach the Data Relay proxy endpoint.

Typical model:

```text
Firewall:
ALLOW Closed-Network → Data-Relay-Server:6080
DENY  Closed-Network → Internet:any
```

Data Relay then enforces destination-level policy.

This separation is intentional.

The product should make required firewall rules easy to document and validate, but must not silently change the network perimeter.

---

# 17. Product Advantages

## 17.1 One Product for Both Directions

```text
External → Internal
Secure Remote Access

Internal → External
Controlled Egress
```

Both are managed from one server and one operational model.

## 17.2 Agentless Outbound Connectivity

Protected outbound hosts require no Data Relay/FRP software installation.

Standard proxy configuration is sufficient.

## 17.3 FQDN-Oriented Egress Control

This reduces the operational burden of maintaining large/changing destination IP lists for services using DNS/CDN infrastructure.

## 17.4 Default-Deny Security Model

Only approved connections are relayed.

## 17.5 Easier Than General-Purpose Proxy Platforms

The product should provide simple lifecycle objects instead of requiring users to manage large Squid/Envoy configuration files.

## 17.6 Stable Egress Source

Approved outbound traffic exits through the Data Relay server, allowing external services to see a predictable source IP when the server itself has a stable public address.

## 17.7 Good Fit for Restricted Networks

The design is particularly useful where:

- direct Internet access is prohibited
- a few update/API/license endpoints are still required
- firewall policies are difficult to manage
- remote support access is also required

---

# 18. Product Positioning

Data Relay should **not** position itself as a Secure Web Gateway.

Do not compete on features such as:

- content inspection
- web categories
- DLP
- malware inspection
- CASB
- TLS decryption
- enterprise user/browser policy

The intended position is:

> **Secure Connectivity for Isolated Networks**

Core message:

> **Inbound: expose only the internal services you need.**
> **Outbound: allow only the Internet services you need.**

Or more simply:

> **필요한 연결만, 더 안전하고 더 쉽게.**

---

# 19. Development Roadmap

## Phase DR-0 — Preserve Existing Inbound Foundation

**Status: EXISTING FOUNDATION**

Goal:

> Keep current FRP-based remote-access functionality stable while adding the new product pillar.

Rules:

- no FRP fork
- no regression of enrollment/identity/service lifecycle
- existing Access Control remains independent from egress policy
- no broad rename before feature correctness is proven

---

## Phase DR-1 — Product Identity & Architecture Definition

**Status: PLANNED**

Goal:

> Introduce Data Relay as the product-level identity and define the two connectivity planes.

Deliverables:

- update Product Master product definition
- add architecture diagram
- define `Secure Remote Access` and `Controlled Egress`
- explicitly state agentless egress requirement
- define network responsibility boundary
- define v1 out-of-scope list
- retain FRP as inbound transport engine
- decide naming migration policy without mass-renaming implementation yet

Acceptance:

```text
Product purpose is understandable without knowing FRP.
Inbound and outbound responsibilities are clearly separated.
No ambiguity that outbound hosts are agentless in v1.
```

---

## Phase DR-2 — Controlled Egress Core MVP

**Status: PLANNED**

Goal:

> Prove that an agentless closed-network host can reach approved Internet destinations and nothing else through Data Relay.

Required implementation:

- server-side egress gateway service
- HTTP forward proxy
- HTTPS CONNECT
- source IP/CIDR ACL
- exact FQDN + port allowlist
- default deny
- basic connection audit
- service lifecycle integration

Minimum Real E2E:

```text
Closed host configured with HTTP_PROXY / HTTPS_PROXY
Approved HTTP destination      = PASS
Approved HTTPS destination     = PASS
Unapproved destination         = DENY
Unapproved port                = DENY
Unapproved source              = DENY
Gateway restart                = policy preserved
```

---

## Phase DR-3 — Egress Policy & CLI Integration

**Status: PLANNED**

Goal:

> Make egress policy easier to operate than editing a general-purpose proxy configuration file.

Required:

- `egress-control` authoritative state
- Egress Profile CRUD
- destination add/remove
- source CIDR add/remove
- enable/disable lifecycle
- show/status commands
- audit integration
- backup/restore
- doctor checks
- deterministic config generation/runtime loading

Guardrail:

Inbound Access Control and Egress Control may share utility code and UX patterns, but their authoritative policy semantics must remain separate.

---

## Phase DR-4 — Security Hardening

**Status: PLANNED / RELEASE BLOCKER**

Goal:

> Ensure the egress gateway cannot be abused as an open proxy or SSRF/pivot mechanism.

Required:

- robust FQDN canonicalization
- DNS resolution validation
- private/local/link-local/reserved destination rejection
- cloud metadata protection
- DNS rebinding resistance
- safe CONNECT parsing
- destination port restrictions
- IP literal policy
- connection and idle timeouts
- concurrency/resource limits
- fail-closed state loading
- sensitive-data-safe logging
- malformed input tests

No release of Controlled Egress as stable before this phase passes.

---

## Phase DR-5 — Real E2E & Compatibility Validation

**Status: PLANNED**

Goal:

> Validate real applications rather than only synthetic proxy tests.

Initial application matrix should include representative tools such as:

```text
curl
wget
apt
Git
package manager / update workflow where available
vendor/API style HTTPS request
```

Real E2E must verify:

- approved destination success
- denied destination failure
- DNS address changes do not require policy rewrite when FQDN is unchanged
- restart persistence
- backup/restore
- malformed policy fail-closed
- source CIDR behavior through real NAT/firewall environments
- audit correctness
- no secret/payload logging

Follow the existing release principle that actual product bugs found during scenario execution are collected, classified, fixed, and then targeted regressions are run before final release qualification.

---

## Phase DR-6 — Product Documentation & Field Usability

**Status: PLANNED**

Required documentation:

- Product Overview
- Secure Remote Access guide
- Controlled Egress quick start
- firewall requirements
- proxy configuration examples
- Egress Profile examples
- security model
- supported/unsupported applications
- NAT/source-IP limitation
- troubleshooting/doctor guide

The quick-start path should make the basic deployment understandable in minutes:

```text
1. Install Data Relay Server
2. Allow the closed network to reach the proxy endpoint
3. Create an Egress Profile
4. Configure HTTP_PROXY / HTTPS_PROXY on the protected host/application
5. Verify approved destination works
6. Verify non-approved destination is denied
```

---

## Phase DR-7 — Demand-Driven Expansion

**Status: DEFERRED / DEMAND DRIVEN**

Candidates:

- fixed TCP egress
- SOCKS5
- PAC
- additional audit/reporting convenience
- reusable organization-level profile templates
- stronger host identity if a secure agentless approach is later approved

Do not implement these because competitors have them. Add them only for repeated field requirements.

---

# 20. Testing Strategy Additions

Controlled Egress adds a new security test category.

Minimum layers:

```text
Unit
↓
Policy Parser
↓
Proxy Protocol Tests
↓
Security / SSRF Tests
↓
Integration
↓
CLI Lifecycle
↓
Backup / Restore
↓
Real E2E
```

Security regression cases must include at least:

- localhost destination
- RFC1918 destination
- link-local destination
- metadata destination
- IPv6 local/private destinations
- malicious/invalid hostnames
- wildcard boundary bypass attempts
- destination port bypass attempts
- malformed CONNECT requests
- DNS rebinding-style resolution changes
- corrupted/missing policy file
- gateway restart during active/idle connections

The test suite must prove not only that approved traffic works, but that **unapproved traffic cannot escape**.

---

# 21. Architecture Guardrails — New Additions

The existing Product Master guardrails remain in force, plus:

## Agentless Egress Must Stay Agentless

Do not require FRP client installation on protected outbound hosts for the base Controlled Egress product.

## Do Not Force FRP into the Egress Data Path

Use FRP where it solves inbound connectivity. Do not add unnecessary FRP components to standard forward-proxy traffic.

## No Open Proxy

The egress gateway must never default to broad anonymous Internet relay.

## No TLS Inspection

Controlled Egress v1 does not terminate or inspect destination TLS traffic.

## No TLS Proxy Endpoint in v1

Explicitly deferred by product decision.

## No mTLS Client Identity in v1

Explicitly deferred by product decision.

## No Automatic Firewall/DNS Changes

Network perimeter control remains administrator-owned.

## No SWG/SASE Scope Creep

Do not add DLP, CASB, malware scanning, web categorization, TLS decryption, or browser security functionality to satisfy generic enterprise-security feature comparisons.

---

# 22. Product Success Criteria

The new product direction is successful when a user unfamiliar with FRP can understand and achieve both workflows.

### Workflow A — Remote Access

```text
Need to support an internal server
        ↓
Publish only the required service
        ↓
Connect securely through Data Relay
```

### Workflow B — Restricted Internet Access

```text
Internal server has no general Internet access
        ↓
Configure standard proxy
        ↓
Allow only required update/API/license FQDNs
        ↓
Everything else remains blocked
```

Operational success means:

- no general VPN required
- no broad Internet opening required
- no Squid-style manual config management for basic cases
- no agent required for outbound protected hosts
- minimal firewall changes
- clear audit trail
- simple CLI lifecycle
- fail-closed security behavior

---

# 23. Final Product Vision

The long-term product experience becomes:

```text
                    DATA RELAY

              Install Server Once
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
Secure Remote Access      Controlled Egress
        │                         │
External → Internal       Internal → External
        │                         │
FRP Client/Gateway        Agentless Proxy Client
        │                         │
Approved Services         Approved Destinations
        │                         │
        └────────────┬────────────┘
                     │
              Central Policy
                  + Audit
                  + Doctor
                  + Backup
```

The core product statement is:

> **Data Relay securely connects isolated networks without opening full network access.**

And the operating principle remains:

> **Simple to deploy.**
> **Simple to understand.**
> **Safe to operate.**
> **Lightweight by design.**

