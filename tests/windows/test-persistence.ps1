# test-persistence.ps1 — enroll-once semantics with mocked state
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    Assert-FrpTrue (-not (Test-FrpIsEnrolled)) 'not enrolled initially'

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
        -FrpServerPort 443 -Hostname 'win-test' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'wss' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 443 -Token 'tok-deadbeef' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null

    Assert-FrpTrue (Test-FrpIsEnrolled) 'enrolled after state+identity+toml'

    $rc = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' `
        -CaSha256 ('0' * 64) -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload
    Assert-FrpEqual 2 $rc 'refuse re-ticket when enrolled'

    $mid2 = Get-FrpOrCreateClientId
    Assert-FrpEqual $mid $mid2 'client-id persists'

    Write-FrpTestPass 'test-persistence'
} finally {
    Remove-FrpWindowsTestRoot
}
