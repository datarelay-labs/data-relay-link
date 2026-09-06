# test-enroll-list-mapping.ps1 — Get-FrpEnrollServiceList wire mapping from a draft
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60020; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    Add-FrpDraftService -Preset 'custom' -Id 'web' -Name 'Web' -TargetHost '10.0.0.5' -TargetPort 8080 | Out-Null
    Add-FrpDraftService -Preset 'ssh' -SshUser 'alice' | Out-Null
    Set-FrpDraftServiceEnabled -Id 'web' -Enable $false | Out-Null

    $draftMap = Get-FrpDraftServiceMap
    Assert-FrpEqual 3 $draftMap.Count 'three pending services'

    $enrollList = Get-FrpEnrollServiceList -Services $draftMap
    # Disabled services are never sent to the allocator.
    Assert-FrpEqual 2 @($enrollList).Count 'only enabled services in enroll list'
    $ids = @($enrollList | ForEach-Object { $_.id })
    Assert-FrpTrue ($ids -contains 'rdp') 'rdp present'
    Assert-FrpTrue ($ids -contains 'ssh') 'ssh present'
    Assert-FrpTrue (-not ($ids -contains 'web')) 'disabled web excluded'

    $rdpWire = @($enrollList | Where-Object { $_.id -eq 'rdp' })[0]
    Assert-FrpEqual 'custom' $rdpWire.preset 'rdp local alias maps to wire preset custom'
    Assert-FrpEqual 3389 ([int]$rdpWire.local_port) 'rdp local port kept'

    $sshWire = @($enrollList | Where-Object { $_.id -eq 'ssh' })[0]
    Assert-FrpEqual 'ssh' $sshWire.preset 'ssh preset kept'
    Assert-FrpEqual 'alice' $sshWire.ssh_user 'ssh_user forwarded on wire'

    # None of the wire entries carry remote_port or enabled (server-facing shape only).
    foreach ($entry in $enrollList) {
        Assert-FrpTrue (-not ($entry.PSObject.Properties.Name -contains 'remote_port')) 'wire entry has no remote_port'
        Assert-FrpTrue (-not ($entry.PSObject.Properties.Name -contains 'enabled')) 'wire entry has no enabled flag'
    }

    Write-FrpTestPass 'test-enroll-list-mapping'
} finally {
    Remove-FrpWindowsTestRoot
}
