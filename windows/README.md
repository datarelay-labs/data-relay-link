# Windows client

See [docs/WINDOWS_CLIENT.md](../docs/WINDOWS_CLIENT.md) for the full user guide.

## Stable validation

Current release (FINAL AUDIT CLOSURE): **Data Relay Link v2.3.1** with pinned FRP **0.71.0**.

| Environment | v2.3.1 validation claim |
| --- | --- |
| Windows 10 / PowerShell 5.1 | **Real E2E validated** |
| PowerShell 7 | **CI validated**; same-host Real E2E is claimed only where `pwsh` is actually installed |

The qualified Windows path includes installation/enrollment, SYSTEM Scheduled Task persistence, lifecycle operations, reboot/autostart, and real service connectivity as applicable to the release E2E matrix.

## Zero-Touch bootstrap

After the admin issues a Windows bootstrap command, keep the production trust flow as:

```text
download
-> SHA256 verify
-> powershell.exe -File
```

Do **not** replace this with `irm ... | iex`.

Example after downloading `install-client.ps1` and verifying its SHA256 against the release `SHA256SUMS`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-client.ps1 -ZeroTouch `
  -AllocatorUrl https://YOUR_HOST/enroll `
  -CaSha256 <DER_SHA256> `
  -BootstrapTicket 'bt1.<id>.<secret>'
```

## Lifecycle

```text
tools\frp-client.cmd start|stop|status|info|update|uninstall|doctor
```

The Windows client reuses the same server enrollment and management model. It does not fork a Windows-only API.
