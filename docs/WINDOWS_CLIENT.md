# Windows Client Guide

Supported OS: **Windows 10 / 11 / Server 2019+** (amd64), Windows PowerShell **5.1** or PowerShell **7+**.

This client reuses the existing Data Relay Link allocator protocol (bootstrap redeem, enroll, CA pin, PBKDF2 token wrap, ECDSA management identity). It does **not** introduce a Windows-only enrollment API.

FRP pin: **0.71.0** Windows amd64 (`frp_0.71.0_windows_amd64.zip`).

## Install layout

```text
C:\ProgramData\drlink\
  bin\frpc.exe
  config\frpc.toml
  state\client-state.json, client-id, client-identity.*
  certs\allocator-ca.crt
  logs\frpc.log, frpc.pid
  tools\FrpClient.ps1, drlink.cmd, frp-client.cmd
  version
```

For non-Windows test hosts (pwsh on Linux CI), set `FRP_WINDOWS_ROOT` (default `/tmp/drlink-windows-test`).

## Zero-touch enrollment

1. On the server, create a zero-touch / bootstrap ticket for the Windows client (RDP-first presets are typical).
2. On the Windows host, download `windows/install-client.ps1` over HTTPS.
3. Verify the script SHA256 against the release `SHA256SUMS`.
4. Run with `-File` (never `irm | iex`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-client.ps1 -ZeroTouch `
  -AllocatorUrl https://YOUR_PUBLIC_HOST/enroll `
  -CaSha256 <allocator-ca-DER-SHA256> `
  -BootstrapTicket 'bt1.<id>.<secret>'
```

Environment equivalents: `FRP_ALLOCATOR_URL`, `FRP_ALLOCATOR_CA_SHA256`, `FRP_BOOTSTRAP_TICKET`.

### What zero-touch does

1. Fetches `/ca.crt` with a **one-shot** TLS exception, then pins DER SHA-256 (`FRP_ALLOCATOR_CA_SHA256`). Later calls use the pinned CA only — **no permanent global TLS bypass**.
2. Redeems the bootstrap ticket (`POST /bootstrap/redeem`).
3. Generates an ECDSA P-256 management identity (DPAPI-wrapped private key on Windows).
4. Enrolls (`POST /enroll`) with enrollment HMAC + public key.
5. Decrypts the FRP token (OpenSSL `Salted__` + PBKDF2-HMAC-SHA256 iter 200000 + AES-256-CBC).
6. Writes `frpc.toml` and downloads `frpc.exe` (HTTPS + SHA256 verify, zip-slip safe).
7. Starts `frpc` in the background.

### ENROLL ONCE / RUN MANY TIMES

If identity + config already exist and install completed, zero-touch **refuses** another ticket and tells you to run `frp-client start`. Port reservations and machine identity stay stable across restarts.

If enrollment finished but binary download/start did not (`install_status=enrolled_incomplete`), re-running the installer **resumes** with the same identity and reserved ports — it does not redeem a new ticket or mint a new management key.

### Zero-service (management-only)

When the redeemed ticket carries `services: []`, Windows keeps an empty service list. It does **not** invent an RDP mapping. Management identity remains enrolled; `frpc` is not started until a service exists.

### TLS

Pinned allocator CA verification and hostname/IP SAN checks both apply on the .NET HTTPS path. A trusted CA with the wrong hostname fails. Set `FRP_WINDOWS_FORCE_DOTNET_HTTP_HTTP=1` only in tests to exercise that path; production prefers `curl --cacert` when present.

### Updates, PID, secrets

- `drlink update engine` (and legacy bare `update`) refreshes pinned `frpc.exe` with SHA256 verify; failure restores binary, metadata, config, and prior running/stopped state (`RECOVERY_REQUIRED=YES` if rollback itself fails).
- `drlink update project` does **not** download a project artifact in this release. On an installed client, re-run the canonical Windows installer to refresh management tools (identity/ports preserved). Developers/CI may set `FRP_WINDOWS_PROJECT_SRC` to a `windows/` tree.
- Check modes are distinct: `update project -Check` (project only), `update engine -Check` (engine Would download), `update --check` (combined).
- Stop kills only a PID whose recorded exe matches the managed `frpc.exe`.
- Secret ACL application is fail-closed on Windows.

## RDP

Default Windows preset exposes TCP **3389** (`preset` treated as RDP in `frp-client info`):

```text
mstsc /v:PUBLIC_HOST:REMOTE_PORT
```

### Security caveats (honest)

- This tool does **not** enable Remote Desktop, open firewall rules, or set Windows credentials.
- Prefer **Network Level Authentication (NLA)** and strong local/domain accounts.
- Treat the public mapping like any internet-exposed RDP service; use VPN or allowlists when possible.
- The FRP token and bootstrap ticket are secrets — never paste them into tickets, chat, or logs.

## Multi-service

Pass `-ServicesJson` with a JSON array of services (`id`, `local_ip`, `local_port`, `preset`, optional `ssh_user` / `name`). Client-side `preset: "rdp"` is sent to the server as `custom` (server allow-list is `ssh|http|https|custom`) while local state keeps RDP-friendly display.

## single443 / WSS

When the allocator returns `frp_transport=wss`, the client writes:

- `serverPort = 443`
- `transport.protocol = "wss"`
- `transport.tls.trustedCaFile` = pinned allocator CA

FRP hard-codes the websocket path `/~!frp` (not configurable).

## LAN gateway

A Windows PC can forward LAN targets by setting `local_ip` to a reachable LAN address (same semantics as Linux). Ensure Windows routing/firewall allows frpc to reach that target. This project does not reconfigure host firewall or routing.

## Lifecycle

```text
tools\drlink.cmd start
tools\drlink.cmd stop
tools\drlink.cmd status
tools\drlink.cmd info
tools\drlink.cmd update [--check]
tools\drlink.cmd uninstall
tools\drlink.cmd doctor
tools\drlink.cmd autostart
```

| Command | Behavior |
| --- | --- |
| `start` / `stop` | Idempotent; manages only the PID recorded under `logs\frpc.pid` |
| `info` | Prints `mstsc` / `ssh` / HTTP(S) URLs without secrets |
| `update` | Replaces `frpc.exe` after SHA256 verify; preserves identity and ports; transactional rollback of managed files + process state |
| `uninstall` | **LOCAL SOFTWARE REMOVED, SERVER RESERVATIONS PRESERVED**; removes the product autostart task |
| `autostart` | Show / enable / disable the product Scheduled Task (`FRPAutoDeployClient`) |

## Reboot / autostart

Enrollment with enabled services registers a product-owned Scheduled Task
named **`FRPAutoDeployClient`**. It runs `frp-client start` as **SYSTEM** at
system boot (ONSTART), so `frpc` comes back without an interactive login.
Management-only (zero-service) clients do not register the task. Use
`frp-client autostart` to inspect, enable, or disable it. Enrollment state
under `ProgramData` persists across reboot.

## Unsupported / out of scope

- ARM64 Windows packages (amd64 only in this release)
- Automatic firewall changes
- Automatic RDP enablement or credential provisioning
- Forked Windows-only enrollment APIs

## Security summary

- No `irm | iex`
- No secrets in `client-state.json` or status/info output
- CA pin required for first enrollment
- Identity private key: DPAPI on Windows; plain restricted file only under Linux test root (`FRP_WINDOWS_ROOT`) with a warning
