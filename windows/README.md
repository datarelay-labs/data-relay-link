# Windows client

See [docs/WINDOWS_CLIENT.md](../docs/WINDOWS_CLIENT.md) for the full user guide.

## Release identity

Current development target: **Data Relay Link 2.4.0** with pinned Relay Engine **FRP 0.71.0**. The documented stable baseline is **v2.3.0**. **v2.2.1** is an older published release. **v2.3.1** was not manufactured. There is no stable **v2.4.0** tag yet, so this page does not claim a current stable Windows release.

| Environment | Current claim |
| --- | --- |
| Windows 10 / PowerShell 5.1 | Final Full Real E2E on the exact candidate HEAD is still required |
| PowerShell 7 | CI may validate the client; same-host Real E2E is claimed only where `pwsh` is actually installed and the final E2E matrix records it |

The Windows path under qualification includes installation/enrollment, SYSTEM Scheduled Task persistence, lifecycle operations, reboot/autostart, and real service connectivity as applicable to the release E2E matrix.

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
tools\drlink.cmd start|stop|status|info|update|uninstall|doctor
```

`tools\frp-client.cmd` remains as a compatibility wrapper for the same operations.

The Windows client reuses the same server enrollment and management model. It does not fork a Windows-only API.
