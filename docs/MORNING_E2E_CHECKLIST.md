# Morning Real E2E Checklist (template)

> **Documentation examples only.** Values below use RFC documentation
> addresses (`203.0.113.0/24`) and `example.invalid` names. They are not live
> lab inventory.

Use this as a short operator template before a Real E2E session.

## Preflight

- [ ] Candidate HEAD recorded
- [ ] Controller can reach example server `203.0.113.10`
- [ ] Passwordless sudo available on disposable clients
- [ ] No secrets pasted into chat/docs

## Matrix (fill with local aliases; do not publish live IPs)

| Platform | Alias (local only) | Result |
|----------|--------------------|--------|
| Ubuntu physical | | |
| Rocky 8 | | |
| Rocky 9 | | |
| Amazon Linux 2023 | | |
| Amazon Linux 2 | portability/CI unless real host | |
| macOS | | |
| Windows PS5.1 | | |
| Windows PS7 | CI / host if `pwsh` present | |

## Security reminders

- Windows: download → SHA256 → `powershell.exe -File` (never `irm | iex`)
- Preserve CLIENT ID / ports on update
- Rocky9 rescue infrastructure (if used) stays independent of product uninstall
