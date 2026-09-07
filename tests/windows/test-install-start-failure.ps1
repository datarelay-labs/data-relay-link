# test-install-start-failure.ps1 — Start-FrpClient failure must fail install
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
            local_port = 3389; remote_port = 60001; enabled = $true
        }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null

    $env:FRP_WINDOWS_SKIP_DOWNLOAD = '1'
    $threw = $false
    $msg = ''
    try {
        Complete-FrpZeroTouchPostEnroll -SkipDownload -Services $services | Out-Null
    } catch {
        $threw = $true
        $msg = $_.Exception.Message
    }
    Assert-FrpTrue $threw 'start failure must throw'
    Assert-FrpTrue ($msg -match 'frpc') 'error mentions frpc'
    Assert-FrpEqual 'enrolled_incomplete' (Get-FrpInstallStatus) 'status remains incomplete'

    Write-FrpTestPass 'test-install-start-failure'
} finally {
    Remove-Item Env:FRP_WINDOWS_SKIP_DOWNLOAD -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
