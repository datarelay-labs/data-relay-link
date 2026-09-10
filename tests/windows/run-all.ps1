# run-all.ps1 — Windows client test suite
# Invoke child tests with the current host engine so a "PowerShell 5.1" CI job
# actually runs powershell.exe, while PS7 / Linux CI continue to use pwsh.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$failed = 0
$passed = 0

$tests = @(
    'test-crypto.ps1',
    'test-token-decrypt.ps1',
    'test-canonical-sign.ps1',
    'test-config.ps1',
    'test-host-id.ps1',
    'test-security.ps1',
    'test-tls-hostname-negative.ps1',
    'test-persistence.ps1',
    'test-process-control.ps1',
    'test-zero-touch-command.ps1',
    'test-frpclient-entrypoint.ps1',
    'test-rdp-service.ps1',
    'test-zero-service.ps1',
    'test-install-start-failure.ps1',
    'test-partial-resume.ps1',
    'test-pending-enroll-recovery.ps1',
    'test-update-rollback.ps1',
    'test-pid-ownership.ps1',
    'test-acl-fail-closed.ps1',
    'test-multi-service.ps1',
    'test-ca-pinning.ps1',
    'test-uninstall.ps1',
    'test-cross-language.ps1',
    'test-installed-cli-persistence.ps1',
    'test-project-version.ps1',
    'test-draft-crud.ps1',
    'test-enroll-list-mapping.ps1',
    'test-apply-identity-auth.ps1',
    'test-service-cli.ps1',
    'test-reconcile-release.ps1',
    'test-public-hostname.ps1',
    'test-sync-reconcile.ps1',
    'test-autostart.ps1',
    'test-autostart-cli.ps1',
    'test-apply-transaction.ps1',
    'test-client-lock.ps1',
    'test-dpapi-localmachine.ps1'
)

function Get-FrpTestHostExe {
    try {
        $p = (Get-Process -Id $PID -ErrorAction Stop).Path
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    } catch { }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return 'powershell.exe'
    }
    return 'pwsh'
}

$hostExe = Get-FrpTestHostExe
Write-Host ("=== Data Relay Link Windows client tests (host={0} PS={1}) ===" -f $hostExe, $PSVersionTable.PSVersion)
foreach ($t in $tests) {
    $path = Join-Path $root $t
    Write-Host ""
    Write-Host "--- $t ---"
    try {
        & $hostExe -NoProfile -File $path
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAIL $t (exit $LASTEXITCODE)"
            $failed++
        } else {
            $passed++
        }
    } catch {
        Write-Host "FAIL $t : $($_.Exception.Message)"
        $failed++
    }
}

Write-Host ''
Write-Host ("Summary: passed={0} failed={1}" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
