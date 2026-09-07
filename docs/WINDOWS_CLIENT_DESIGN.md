# Windows Client design

Base: current architecture at `origin/feature/macos-client-current-main` (`afc446c`)
Branch: `feature/windows-client-current-main`
FRP pin: **0.71.0** (Windows amd64 zip SHA256 pinned in `lib/frp-common.sh`)

## Reusable server protocol

Windows does **not** fork enrollment. It reuses:

| Area | Contract |
| --- | --- |
| Bootstrap | `POST /bootstrap/redeem` — `bt1.<id>.<secret>` |
| Enroll | `POST /enroll` — enrollment HMAC or mgmt ECDSA |
| CA | `GET /ca.crt` — DER SHA-256 pin via `FRP_ALLOCATOR_CA_SHA256` |
| Token | OpenSSL `Salted__` + PBKDF2-HMAC-SHA256 (200000) + AES-256-CBC |
| Mgmt identity | ECDSA P-256 / SHA-256, canonical JSON schema 1 |
| Services | TCP presets; ports allocated by existing registry |
| single443 | `frp_transport=wss`, path `/~!frp` (FRP hard-coded) |

## Linux-specific vs Windows

| Concern | Linux | Windows |
| --- | --- | --- |
| Installer | `bootstrap-client.sh` | `bootstrap-client.ps1` |
| Paths | `/etc/frp`, `/etc/frp-auto-deploy` | `C:\ProgramData\frp-auto-deploy\` |
| Process | systemd | background process + optional autostart later |
| machine_id | `/etc/machine-id` or random `client-id` | random id persisted under ProgramData |
| Crypto CLI | OpenSSL | .NET `System.Security.Cryptography` |
| HTTPS client | curl `--cacert` | curl.exe when present; else request-local .NET pin |

## Filesystem

```
C:\ProgramData\frp-auto-deploy\
  bin\frpc.exe
  config\frpc.toml
  state\client-state.json
  state\client-id
  state\client-identity.key.dpapi
  state\client-identity.pub
  state\client-identity.mac
  certs\allocator-ca.crt
  logs\frpc.log
  logs\frpc.pid
  tools\FrpClient.ps1
  version
```

Sensitive files: ACL for `SYSTEM` + `Administrators` only.

## Zero-touch UX

`create zero-touch` → platform menu → Linux (existing) or Windows (RDP-first).

Windows one-line (no `irm | iex`):

1. Download `bootstrap-client.ps1` to a unique temp path
2. Verify SHA256 against release `SHA256SUMS`
3. Execute with `-File` and env-equivalent parameters

## Lifecycle semantics

**ENROLL ONCE / RUN MANY TIMES**

- First run: redeem + enroll + write state/config + start frpc
- Later: `frp-client start` uses existing identity/config/ports — no ticket, no re-enroll

Autostart (Service / Task Scheduler) is **optional**, not MVP-blocking.

## Security invariants

- No global TLS bypass
- `/ca.crt` may use one-shot unauthenticated TLS; fingerprint must match
- All later calls use pinned CA
- No ticket/token/private key in logs
- Zip-slip safe FRP extract
- Quoting-safe PowerShell command generation

## Test strategy

- Cross-language ECDSA + token vectors (Python ↔ PowerShell)
- Local FRP TCP forwarding E2E on `windows-latest`
- Mock allocator HTTPS where feasible
- Linux `./tests/run-all.sh` must remain PASS
