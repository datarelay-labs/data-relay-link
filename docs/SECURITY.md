# Security architecture

This document describes the security model of `Data Relay Link` **2.3.0**.
It is not a certification, audit report, or guarantee against a compromised
root account.

Pinned FRP version: **0.71.0**. Product version is independent of the
management protocol version (`schema: 1` in signed requests) and of FRP.

## 1. FRP tunnel authentication

The FRP control/data tunnel uses:

- FRP native TLS on Direct mode (`transport.protocol = tcp`, `transport.tls.enable = true`)
- FRP WSS on Enterprise single-443 (`transport.protocol = wss` plus `trustedCaFile` pinning the allocator CA)
- the FRP server token (`/etc/frp/server_token`)

In single-443 mode nginx terminates TLS on public TCP/443 with the project
leaf certificate. The frontend proxies allocator paths to loopback HTTPS
and verifies that backend with `proxy_ssl_verify on` as `DNS:localhost`.
The frps backend on localhost does not use `tls.force`;
authentication remains the FRP token. Plain WebSocket (`websocket` without
TLS) is not a supported production transport.

The FRP token authenticates the **tunnel only**. It is not a management API
credential, not an Enrollment Code, and not a Bootstrap Ticket.

## 2. Management-plane transport

Enrollment and signed client management use **HTTPS only**.

- There is no plain HTTP allocator mode.
- There is no HTTP fallback.
- There is no mutual TLS (mTLS).

Clients authenticate to the allocator with a one-time Enrollment Code (or a
short-lived Bootstrap Ticket that redeems into the same enrollment flow), then
with a persistent ECDSA P-256 identity.

## 3. Private CA

The server installer creates a project-managed private CA:

```text
/etc/drlink/pki/ca.key     # secret
/etc/drlink/pki/ca.crt     # public certificate
/etc/drlink/pki/server.key # secret
/etc/drlink/pki/server.crt # public certificate
```

The allocator presents `server.crt`. Clients verify it with the pinned CA.
Software update is **not** CA rotation. A public-host / SAN change may reissue
the **leaf** certificate under the same CA. Rotating or replacing the CA itself
is an advanced manual recovery scenario; this release does not implement CA
rotation.

## 4. CA fingerprint bootstrap

First client install downloads `/ca.crt` once over the configured HTTPS
allocator URL **without** using a `--cacert` file that does not exist yet.
It parses the body as X.509 and checks the SHA256 fingerprint of the
**canonical DER** encoding against `FRP_ALLOCATOR_CA_SHA256`. That hash is the
**CA** certificate, not the nginx/allocator leaf. On success it stores
`/etc/drlink/allocator-ca.crt`. Later allocator calls use
verified HTTPS (`curl --cacert` with that stored CA). This is not TOFU and not
self-verification of a file against itself.

The fingerprint is public trust metadata. It does **not** prove that a
`curl | sudo bash` bootstrap script from GitHub is authentic. Those are
separate trust domains (see below).

## 5. Enrollment Code

A short-lived secret created on the server (`sudo drlink create enrollment`).

- Default TTL: 10 minutes
- Bound to the first machine (`machine-id`) that uses it
- **One-time credential**: after the first successful enrollment (`used_at` set),
  the code cannot be used as a fresh credential again
- Exact lost-response retry is allowed only when the same machine, the same
  management public key, and the same enabled service set are presented; the
  server returns the already-committed allocation without rotating identity
- Rejected: used code + different machine, used code + new management key,
  used code + changed services / authority
- Identity recovery or key rotation requires a **new** Enrollment Code issued
  by an administrator (after `frp-revoke-client` when the old key must be blocked)
- Ordinary service apply/update after enrollment uses the persistent management
  identity (signed requests), not the Enrollment Code
- Entered interactively on manual install; not placed on the command line
- Not the FRP token
- Enrollment requests/responses are HMAC-authenticated
- The enrollment secret is not sent in the HTTPS request body
- The FRP token is returned encrypted (AES-256-CBC / PBKDF2) over verified HTTPS
- Server storage: root-owned mode-0600 JSON under
  `/var/lib/drlink/enrollments/*.json` (secret field stored as issued;
  not hashed or wrapped at rest in the current release)

Needed again only to enroll a new client, recover a lost local identity, or
re-establish trust after `frp-revoke-client`.

## 6. Bootstrap Ticket

Zero-touch (`--one-line`) issues a short-lived ticket that the client redeems
over verified HTTPS **after** CA pinning.

Shared ticket properties (both delivery modes):

- High-entropy secret; hashed at rest on the server
- First-machine bound; same-machine retry is safe until enrollment completes
- After successful enrollment the ticket is marked completed; further redeem
  attempts fail with `BOOTSTRAP_TICKET_USED`
- A different machine is rejected with `BOOTSTRAP_TICKET_BOUND`
- TTL enforced; revocable before use
- Not persisted on the client as the raw ticket
- Must not be logged
- Has no management authority after enrollment completes
- Not the FRP token

### Transitional zt1 mode (v2.1.2 and fallback)

When `bootstrap_hostname` is unset, the ticket is carried **inside** the opaque
`zt1.` package argument. It is **not** placed in the HTTP URL path or query of
the installer fetch. The installer URL is a public immutable release asset; the
sensitive ticket travels only as the `bash -s -- 'zt1.<opaque>'` argument.

### Short URL mode (v2.1.3 Option B)

When `bootstrap_hostname` is configured, the enrollment command is:

```bash
curl -fsSL https://<bootstrap_hostname>/i/<opaque-ticket> | sudo bash
```

In this mode the Bootstrap Ticket **is** present in the HTTP URL path
(`/i/<opaque-ticket>`). That is intentional for the short-command UX and does
**not** weaken the ticket controls above.

Treat the complete `/i/<ticket>` URL as a **short-lived credential**:

- Do not log it (allocator audit already redacts `/i/<ticket>` to `/i/<redacted>`;
  operator reverse proxies must also avoid raw URI logging — see
  `docs/ZERO_TOUCH_SHORT_URL.md`)
- Do not paste it into public tickets or chat
- Do not store it in analytics
- Do not expose it through HTTP referrers

Lifecycle (unchanged binding rules):

- `GET /i/<ticket>` delivers the bootstrap script only — it does **not** consume
  or bind the ticket
- Binding occurs only at `POST /bootstrap/redeem`
- Successful enrollment completes consumption (single-use)

Treat the generated one-line command as sensitive until used, expired, or
revoked.

### Windows Short URL bootstrap

The Windows Short URL appends `?platform=windows`. The returned PowerShell
bootstrap downloads both `SHA256SUMS` and `dist/bootstrap-client.ps1`, verifies
the script with `Get-FileHash -Algorithm SHA256`, and only then executes it with
`powershell.exe -File`. It never uses `irm | iex` or another download-and-execute
pipeline. Windows PS5.1 Real E2E is validated in v2.2.1; PowerShell 7 remains
CI-validated (same real host only when `pwsh` is available).

## 6a. Enrollment retention and purge

Terminal enrollment metadata (`expired`, `completed`, `revoked`) is retained on
disk for `enrollment_retention_days` (default **30**) so operators can review
recent history with `show enrollments`. After that period, records become
eligible for automatic cleanup during enrollment issuance or allocator startup.

- `revoke enrollment` — security lifecycle; blocks pending/bound credentials
- `purge enrollment` — housekeeping lifecycle; permanently removes terminal metadata
- Automatic cleanup is pair-aware for zero-touch (bootstrap ticket + paired enrollment)
- Malformed or inconsistent pairs are never silently deleted (fail closed; see `doctor`)
- Audit log retention is independent; purging enrollment JSON does not delete audit events
- Non-interactive purge requires `FRP_ENROLLMENT_PURGE_YES=yes`

Terminal timestamp policy:

| State | Retention age calculated from |
|-------|------------------------------|
| expired | `expires_at` |
| completed | `completed_at` or `used_at` |
| revoked | `revoked_at` |

## 7. ECDSA management identity

After enrollment, the client keeps a local ECDSA P-256 key:

```text
/etc/frp/client-identity.key   # secret, 0600
/etc/frp/client-identity.pub   # public
/etc/frp/client-identity.mac   # secret MAC material, 0600
```

The private key never leaves the client. The server stores the public key,
fingerprint, MAC secret, and revocation status. Signed management requests use
management schema **1** (independent of project version 2.0.0).

## 8. Nonce and timestamp replay defense

Signed objects bind protocol schema, algorithm, client/machine identity,
operation, timestamp, nonce, and payload digest.

```text
MAX_CLOCK_SKEW=300          # seconds
MGMT_NONCE_TTL=900          # seconds
MAX_NONCES_PER_CLIENT=256
```

Replayed nonces and stale timestamps are rejected. A retry of the same logical
Apply uses a new timestamp/nonce/signature and reuses existing public ports.

`drlink doctor` is read-only and does not consume a nonce.

## 9. Revoke vs release

| Action | Management identity | Port reservations |
| --- | --- | --- |
| `frp-revoke-client` | blocked | kept |
| `frp-release-client` / `frp-release-service` | unchanged | freed |

Revoke is not release. An administrator can still release after revoke.

## 10. Disable vs release

| Action | Publication | Public port |
| --- | --- | --- |
| Disable | stopped | reserved |
| Re-enable | resumed | **same** port |
| Edit (local target) | may change target | **same** port |
| Release | removed | freed for reuse |

Disable is not release.

## 11. Secret vs public inventory

**Secrets**

| Item | Typical path |
| --- | --- |
| FRP server token | `/etc/frp/server_token` |
| Enrollment Code secret | `/var/lib/drlink/enrollments/*.json` (root-owned `0600`; secret stored as issued, not hashed/wrapped) |
| Bootstrap Ticket while valid | `/var/lib/drlink/bootstrap/` (hashed at rest) |
| Client management private key | `/etc/frp/client-identity.key` |
| Management MAC secret | `/etc/frp/client-identity.mac` (server copy on the client record) |
| CA private key | `/etc/drlink/pki/ca.key` |
| TLS server private key | `/etc/drlink/pki/server.key` |
| Generated `frps.toml` / `frpc.toml` | contain the FRP token |

**Public / non-secret metadata**

| Item | Typical path |
| --- | --- |
| CA certificate | `/etc/drlink/pki/ca.crt` |
| CA SHA256 fingerprint | printed by `frp-create-client` |
| Server certificate | `/etc/drlink/pki/server.crt` |
| Management public key | `/etc/frp/client-identity.pub` |
| Service ID, public service port, public hostname (optional DNS alias) | `frp-client-info`, `access-info.txt` |
| Client desired state (no secrets) | `/etc/frp/client-state.json` |

`client-state.json` is the canonical local desired state. `frpc.toml` and
`access-info.txt` are generated artifacts. Do not treat `frpc.toml` as the
document to edit.

## 12. Expected file modes

| Path | Mode |
| --- | --- |
| `/etc/frp/server_token` | `0600` |
| `/etc/drlink/pki/` | `0700` |
| `/etc/drlink/pki/ca.key` | `0600` |
| `/etc/drlink/pki/ca.crt` | `0644` |
| `/etc/drlink/pki/server.key` | `0600` |
| `/etc/drlink/pki/server.crt` | `0644` |
| `/etc/frp/client-identity.key` | `0600` |
| `/etc/frp/client-identity.mac` | `0600` |
| `/etc/frp/client-state.json` | `0600` |
| `/etc/frp/frpc.toml` | `0600` |
| `/etc/frp/frps.toml` | `0600` |
| `/var/lib/drlink/registry.json` | `0600` |
| `/etc/drlink/allocator-ca.crt` | `0644` |
| `/etc/frp/access-info.txt` | `0644` |
| `/etc/drlink/version` | `0644` |

Do not manually edit the registry, `client-state.json`, `frpc.toml`, or
identity files unless performing advanced recovery.

## 13. Trust domains

`curl … | sudo bash` fetches the **installer bundle** from the configured
installer URL (often GitHub `raw.githubusercontent.com`). Integrity of that
script is a GitHub/HTTPS and operator-process concern.

Allocator **CA fingerprint** pins the management CA. It does not attest the
bootstrap script.

Checksums:

- Official FRP archives are checked against pinned SHA256 values
- Repository `SHA256SUMS` covers tracked source/release files
- `scripts/check-frp-compatibility.sh` verifies digests **before** extract/execute
  and writes an atomic PASS report only after required checks succeed

This project does **not** currently ship cryptographic signatures or GitHub
artifact attestations of its own bundles (`release-manifest.json` records
`"signing": false`). SHA256 verification protects against accidental corruption
and many tampering cases when the checksum channel is trusted, but it is **not**
the same as an independently signed release. Residual supply-chain risk remains
accepted for v2.2.x until a low-risk signing/attestation path is added.

## 14. Threat boundaries

| Situation | Boundary |
| --- | --- |
| MITM on allocator before CA pin | Fingerprint mismatch; install must fail closed |
| MITM after CA pin | TLS verification with pinned CA |
| Stolen Enrollment Code | Usable until expiry / first-machine bind |
| Stolen Bootstrap Ticket | Same; one-line command is sensitive |
| Replayed management request | Rejected (nonce/timestamp) |
| Compromised client local root | **Outside** the protection boundary |
| Compromised server root | **Outside** the protection boundary |
| Lost response / retry | New nonce; ports reused, not duplicated |
| Registry corruption | Fail closed; restore from backup |
| Malicious FRP archive | Version/arch/checksum/path-traversal checks |
| Shell metacharacters in zero-touch fields | Values are `shlex`-quoted; control characters rejected |

Local root compromise on the FRP server or client is outside the protection
boundary. File modes reduce accidental exposure; they do not protect secrets
from root.

## 15. Backup and disaster recovery

**Server backup (minimum)**

```text
/etc/drlink/pki/
/etc/frp/server_token
/etc/drlink/config.json
/var/lib/drlink/registry.json
```

Also consider enrollments, bootstrap tickets, and `mgmt-nonces.json`. Store
backups mode `600`. Losing the private CA means existing clients cannot
validate a replacement allocator until trust is re-established (typically
re-enrollment).

**Client**

Client uninstall **intentionally** removes local identity and state. Do not
copy `client-identity.key` over insecure channels. A replacement host is a new
enrollment (or Enrollment Code recovery) even if the server still holds the
old reservation.

| Loss | Supported recovery |
| --- | --- |
| Server software lost, state preserved | Re-run the server installer; CA/token/registry reused |
| Server host completely lost | Restore the backups above, then reinstall |
| Client local state lost | New enrollment or Enrollment Code recovery |
| Client identity lost | Enrollment Code recovery (`frp-revoke-client` if the old key must be blocked) |
| CA lost or compromised | Advanced manual recovery; **not** solved by `drlink update` |
| Registry lost | Restore `registry.json` from backup; the installer will not invent reservations |

Token rotation is not automatic. Reinstall preserves the existing FRP token.

## 16. Service Access Control (defense-in-depth)

Published TCP services may be `PUBLIC` (default) or `ALLOWLIST` using Named
Access Lists. Authorization runs in the FRP NewUserConn plugin on loopback
only. For ALLOWLIST services, plugin/policy failure **denies** the user
connection (fail closed). PUBLIC services keep open access when policy loads
successfully.

Access Control does **not** replace target authentication. Keep SSH keys,
application auth, and database credentials enabled. Do not apply Service
Access Lists to FRP control, enrollment/management, or the single-443
frontend itself. Unmapped or drifted published-service proxy names fail
closed (DENY); they must never fall back to PUBLIC.

Connection authorization events are written to a bounded local log
(`/var/log/drlink/access-conn.jsonl`). Enrollment tickets, FRP
tokens, CA keys, and passwords are not logged.

If an upstream device SNATs clients, allowlists must use the source address
observed by `frps`.

## 17. Controlled Egress (agentless outbound)

Controlled Egress is a **separate policy plane** from inbound Access Control.

Authoritative state: `/var/lib/drlink/egress-control.json`
Connection log: `/var/log/drlink/egress-conn.jsonl`
Daemon: `drlink-egress.service` (default listen `0.0.0.0:6102`, outside published pool `6000–6098`)

Security contract:

- Default DENY; missing/corrupt/invalid policy fails closed
- Primary caller authorization is source IP/CIDR (no agent on protected hosts)
- Destinations are FQDN + port + **required protocol** `http|https`
  - `http`: absolute-form proxy requests only
  - `https`: `CONNECT` + TLS ClientHello SNI binding; ECH denied; no TLS interception
- Wildcard hosts are checked against a **pinned Public Suffix List**
  (`lib/frp_public_suffix.py`, `lib/data/public_suffix_list.dat`); bare public-suffix wildcards are rejected
- IP literals denied by default
- Server-side DNS; every resolved candidate IP is validated before connect
- Reject loopback, RFC1918, link-local, ULA, metadata (`169.254.169.254`), multicast/reserved
- Resolve once → validate → connect to that exact IP (rebinding-safe)
- Policy reload Option B: gateway reloads policy on file mtime change; new authorizations always use current policy (no stale-while-revalidate for allow decisions)
- Do not log Proxy-Authorization, cookies, bodies, or TLS payloads
- Egress failure must not take down inbound `frps`; inbound Access Control remains independent
- Service unit runs as dedicated non-root user `drlink-egress` with systemd hardening; registry/enrollment secrets stay root-owned and outside egress write paths

Windows Update over the proxy is possible with an explicit destination set. **Delivery Optimization peer traffic is out of Controlled Egress scope** — keep DO disabled or use WSUS/managed update paths on closed hosts.

Operator CLI (resource-first): `drlink egress list` / `egress status` / safe create→source→destination+protocol→test→enable. See `docs/CONTROLLED_EGRESS.md`.

## 18. Mixed product versions

Project **2.1.0** does not change management protocol schema `1`. An already
enrolled **1.9.1** or **2.0.0** client is expected to keep its tunnel and signed
management against a **2.1.0** Direct-mode server. Product version is not
management protocol version. There is no forced client re-enrollment on this
upgrade.

A **2.0.0** client cannot speak FRP WSS. Switching the server to single-443
requires **2.1.0+** clients and an Apply after cutover; it is not a silent
transport upgrade.
