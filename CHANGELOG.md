# Changelog

## Unreleased

## 2.2.1 — 2026-09-08

Maintenance / hardening release on pinned FRP **0.71.0**. Does not move or
retag published **v2.2.0**.

- macOS / libedit Tab completion: detect readline backend and bind libedit
  completion; PTY regression coverage plus macOS CI job
- FRP compatibility gate fail-closed: digest-before-extract, atomic PASS
  report; bump script validates report content
- Public metadata sanitization: morning checklists use RFC5737 templates;
  `scripts/check-public-metadata.sh` scanner
- Docs currency for post-v2.2.0 install/signing residual risk notes

### Compatibility

Already enrolled 2.2.0 clients remain compatible during a server-first upgrade
window. Do not upgrade clients ahead of the server. FRP remains **0.71.0**.

## 2.2.0 — 2026-09-07

Feature and platform release. Pinned FRP upgraded **0.70.1 → 0.71.0**.

- Qualifies macOS Apple Silicon (launchd), Windows amd64 (hash-verified
  PowerShell `-File` bootstrap), Manual Group MVP, `public_hostname`, and
  Rocky Linux 9.4 on the supported platform matrix
- Upstream FRP pin moved to **0.71.0** after compatibility review (WebSocket
  path `/~!frp` unchanged; config verify PASS; no product config migration)
- Enrollment retention hardening: terminal records (`expired`, `completed`,
  `revoked`) retained for `enrollment_retention_days` (default 30), then
  pair-aware automatic cleanup; `purge enrollment` / `purge enrollments
  --older-than` for manual housekeeping; audit log retention unchanged
- Operator checklist: `docs/MORNING_E2E_CHECKLIST.md`

### Compatibility

Already enrolled 2.1.3 clients remain compatible during a server-first upgrade
window. Do not upgrade clients ahead of the server. FRP rolling window supports
`frps 0.71.0 + frpc 0.70.1` during server-first FRP binary upgrade; product
policy still requires project server upgrade before clients.

## 2.1.3 — 2026-09-04

Feature release on top of published **v2.1.2**. FRP remains pinned at
**0.70.1**. Published field installs stay on **v2.1.2** until `v2.1.3` is tagged.

- Ideal Zero-Touch `/i/<ticket>` short URL via optional `bootstrap_hostname`
  and an operator-owned reverse proxy (Option B; see
  `docs/ZERO_TOUCH_SHORT_URL.md`)
- Keeps the transitional `zt1.` package command when `bootstrap_hostname` is
  unset; no insecure TLS (`curl -k`) on the Zero-Touch path
- Allocator short-URL embedding reloads config so fresh installer URLs are
  used without requiring a process restart
- Server bootstrap embeds `frp_zero_touch.py` helper for package/short-URL
  generation

### Compatibility

Already enrolled 2.1.2 clients remain compatible during a server-first upgrade
window. Do not upgrade clients ahead of the server.

## 2.1.2 — 2026-09-04

Maintenance release. FRP remains pinned at
**0.70.1**.

- Correctness hardening: last-service release keeps the Client record;
  CLIENT ID selector precedence; bootstrap completion fail-closed
- Upgrade safety: transactional server/client project update with rollback;
  server-first mixed-version policy (`Server N + Client N-1` supported;
  `Client N + Server N-1` blocked as `SERVER_VERSION_TOO_OLD` before mutation);
  identity, CA, FRP token, ports, labels/notes/tags, and public_hostname
  preservation
- Backup/audit hardening: ticket/package redaction, audit rotation,
  rotated audit inclusion in backup; same-version restore only
  (cross-version restore fail-closed before mutation)
- Release metadata completeness for official install/uninstall artifacts
- Transitional shorter Zero-Touch: publicly trusted installer plus opaque
  `zt1.` package (no insecure TLS). Ideal `/i/<ticket>` short URL trust model
  remains pending in this release line
- Rocky Linux 8 container regression coverage in the distro matrix

### Compatibility

Already enrolled 2.1.1 clients remain compatible during a server-first upgrade
window. Do not upgrade clients ahead of the server.

## 2.1.1 — 2026-09-04

Stable release. FRP remains pinned at **0.70.1**.

- Optional public hostname access alias for client/service display and operator
  access hints (falls back to Public IP when unset)
- First-class `create zero-touch` in `frpctl` (guided SSH-only and multi-service
  workflows, including remote LAN targets)
- Zero-touch guided menu shows SSH only / Configure services / Back;
  Management-only remains available to the backend but is hidden from the
  guided menu
- CLI discoverability and Tab completion behavior retained (first-press
  candidates, no command dispatch on Back)
- `frpctl` verb/resource grammar, enrollment listing without secrets, and
  CLIENT ID as the canonical selector (continued from post-2.1.0 main work)
- Same-version client/server updates compare verified bundle SHA256, not only
  `PROJECT_VERSION`
- Legacy clients without persisted release metadata fail closed on remote
  update until a one-time verified bridge (`docs/FRP_UPGRADE.md`)
- Server install/rerun and project-update migrate official project-managed
  `client_installer_url` values to the current release-line canonical installer
  (`v2.1.1` on stable; `main` on explicit dev). Custom, third-party, look-alike,
  and explicit `FRP_CLIENT_INSTALLER_URL` overrides are preserved
- Manual enrollment and legacy one-line client creation continue to use the
  same persisted installer URL release-line semantics
- Allocator/restore readiness hardening and released-service client-state
  reconciliation

### Compatibility

Already enrolled 2.1.0 clients remain compatible. After a server project update
from 2.1.0, newly generated Zero-touch / enrollment installer commands use the
`v2.1.1` bootstrap URL when the persisted URL was an official managed ref.

## 2.1.0 — 2026-08-29

Stable release. Optional **Enterprise single-443** mode: public TCP/443 carries
allocator HTTPS and FRP control over WSS (nginx frontend, project CA). Direct
mode (443 frps + 6099 allocator HTTPS) remains the default. Published services
stay TCP/6000-6098. FRP remains pinned at **0.70.1**.

- Installer: `FRP_DEPLOYMENT_MODE=direct|single443` and TTY mode prompt
- Enrollment returns `frp_transport` (`tcp` or `wss`); clients pin the stored CA for WSS
- `frpctl status` / `frpctl doctor` show topology and TLS-reset vs closed-port
- Mode switch is an explicit maintenance-window cutover (`FRP_CONFIRM_MODE_SWITCH`)
- HTTP allocator, `curl -k`, and plaintext WebSocket are not used
- Single-443 frontend verifies the loopback allocator as `DNS:localhost`
  (`proxy_ssl_verify on`); distro `nginx.service` autostart is disabled when
  this project installs nginx, and a pre-existing active nginx unit is a
  conflict rather than silently stopped
- `frpctl doctor` checks frontend-proxied `/healthz` and `/ca.crt`, not only
  the allocator backend

See [docs/DEPLOYMENT_MODES.md](docs/DEPLOYMENT_MODES.md).

### Real-environment acceptance

Field-validated on Ubuntu 24.04 x86_64 (direct public-IP server, enterprise-restricted
client, FRP 0.70.1): 1.9.1→2.1.0 server migration, single-443 cutover, HTTPS/443
enrollment, WSS/443 control, published SSH TCP/6000, and client/server reboot
recovery. Before single-443, TLS on non-443 ports was reset; after cutover,
HTTPS and WSS succeeded on TCP/443.

Not field-validated: firewall DNAT / private FRP-server topology, SELinux
Enforcing, ARM64 hosts, OpenSSL 1.0.2 hosts. Details:
[docs/RELEASE_VALIDATION.md](docs/RELEASE_VALIDATION.md).

## 2.0.0 — 2026-08-28

Stable product milestone for `frp-auto-deploy`. This is **not** an upstream FRP
change. FRP remains pinned at **0.70.1**.

### Capabilities

- Secure HTTPS enrollment with a project-managed private CA and DER SHA256 fingerprint bootstrap
- Persistent ECDSA P-256 client management identity after one-time enrollment
- NAT-aware public vs listen port model (public control/allocator ports may differ from listen ports; published services stay 1:1)
- Multi-service TCP clients (SSH, HTTP, HTTPS passthrough, custom TCP)
- Lifecycle hardening: add / edit / disable / re-enable / release, with port preservation on edit/disable
- Install and update rollback where the operation can be verified
- Read-only `frpctl doctor` / `frpctl doctor --json`
- Docker userspace distro matrix (Ubuntu 22.04/24.04, Rocky 9, AlmaLinux 9, Amazon Linux 2023, Amazon Linux 2)
- Zero-touch SSH bootstrap (`frp-create-client --one-line --ssh`) using a short-lived Bootstrap Ticket
- Manual Enrollment Code flow remains fully supported

### Security

- No plain HTTP management or enrollment
- CA pinning and X.509 validation; canonical DER fingerprint
- Nonce and timestamp replay protection
- Hashed bootstrap tickets at rest; first-machine bind; no ticket in the HTTP URL
- FRP archive path-traversal, version, and architecture checks
- Safe uninstall paths (client uninstall does not release server ports; server purge is explicit `--purge --yes`)

### Compatibility

| Area | Status |
| --- | --- |
| FRP | 0.70.1 pinned |
| Ubuntu 22.04 / 24.04 | container PASS; real VM live baseline PASS |
| Rocky Linux 9 | container PASS; LXD systemd PASS; real VM / SELinux Enforcing **NOT_TESTED** |
| AlmaLinux 9 | container PASS; LXD systemd PASS; real VM / SELinux Enforcing **NOT_TESTED** |
| Amazon Linux 2023 | container PASS; LXD systemd PASS; real VM **NOT_TESTED** |
| Amazon Linux 2 | container PASS (including OpenSSL 1.0.2 userspace); real VM / systemd 219 / TTY **NOT_TESTED** |

Already enrolled 1.9.1 clients remain compatible with a 2.0.0 server (management protocol schema 1 is unchanged).

### Known limitations

- TCP services only
- Service NAT is 1:1 port-number mapping
- No automatic firewall, SELinux policy, or SSH account/key management
- Windows client automation is not included
- Real VM / SELinux Enforcing / ARM64 systemd / real OpenSSL 1.0.2 TLS enrollment remain `NOT_TESTED` where listed
- Bundles are checksummed (`SHA256SUMS`); this project does not ship cryptographic signatures of its own installer scripts
