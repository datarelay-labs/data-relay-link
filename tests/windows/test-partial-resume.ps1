# test-partial-resume.ps1 — enrolled_incomplete resumes without re-ticket
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{
            id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'
            local_port = 3389; remote_port = 60002; enabled = $true
        }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null

    Assert-FrpTrue (Test-FrpIsEnrolled) 'enrolled files present'
    Assert-FrpTrue (Test-FrpCanResumeInstall) 'can resume'
    Assert-FrpTrue (-not (Test-FrpIsInstallComplete)) 'not complete'

    $env:FRP_WINDOWS_FAIL_AFTER_ENROLL = '1'
    $threw = $false
    try {
        Complete-FrpZeroTouchPostEnroll -SkipDownload -SkipStart -Services $services | Out-Null
    } catch { $threw = $true }
    Assert-FrpTrue $threw 'fail-after-enroll hook works'
    Assert-FrpEqual 'enrolled_incomplete' (Get-FrpInstallStatus) 'still incomplete'
    Remove-Item Env:FRP_WINDOWS_FAIL_AFTER_ENROLL -ErrorAction SilentlyContinue

    $env:FRP_WINDOWS_SKIP_DOWNLOAD = '1'
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'dummy'
    $rc = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' `
        -CaSha256 ('0' * 64) -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc 'resume succeeds'
    Assert-FrpEqual 'installed' (Get-FrpInstallStatus) 'installed after resume'
    Assert-FrpEqual $mid (Get-FrpOrCreateClientId) 'same client id'

    $rc2 = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' `
        -CaSha256 ('0' * 64) -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload
    Assert-FrpEqual 2 $rc2 'refuse re-ticket when installed'

    Write-FrpTestPass 'test-partial-resume'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_AFTER_ENROLL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_SKIP_DOWNLOAD -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
