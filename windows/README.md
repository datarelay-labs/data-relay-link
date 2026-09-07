# Windows client

See [docs/WINDOWS_CLIENT.md](../docs/WINDOWS_CLIENT.md) for the full user guide.

Quick start (zero-touch, after the admin issues a Windows bootstrap command):

```powershell
# Download install-client.ps1, verify SHA256 against release SHA256SUMS, then:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-client.ps1 -ZeroTouch `
  -AllocatorUrl https://YOUR_HOST/enroll `
  -CaSha256 <DER_SHA256> `
  -BootstrapTicket 'bt1.<id>.<secret>'
```

Lifecycle:

```text
tools\frp-client.cmd start|stop|status|info|update|uninstall|doctor
```

This client reuses the existing server enrollment protocol. It does not fork a Windows-only API.
