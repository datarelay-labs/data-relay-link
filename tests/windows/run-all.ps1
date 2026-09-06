# run-all.ps1 — Windows client test suite (pwsh 7 on Linux CI or Windows)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$failed = 0
$passed = 0
$skipped = 0

$tests = @(
    'test-crypto.ps1',
    'test-token-decrypt.ps1',
    'test-canonical-sign.ps1',
    'test-config.ps1',
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
    'test-update-rollback.ps1',
    'test-pid-ownership.ps1',
    'test-acl-fail-closed.ps1',
    'test-multi-service.ps1',
    'test-ca-pinning.ps1',
    'test-uninstall.ps1',
    'test-cross-language.ps1'
)


Write-Host '=== frp-auto-deploy Windows client tests ==='
foreach ($t in $tests) {
    $path = Join-Path $root $t
    Write-Host ""
    Write-Host "--- $t ---"
    try {
        & pwsh -NoProfile -File $path
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
