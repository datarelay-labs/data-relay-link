# test-reconcile-release.ps1 — released services drop from local state (no ghost proxies)
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId

    $ssh = @{ id = 'ssh'; name = 'SSH'; preset = 'ssh'; local_ip = '127.0.0.1'; local_port = 22; remote_port = 6002; enabled = $true; ssh_user = 'aella' }
    $web = @{ id = 'web'; name = 'Web'; preset = 'custom'; local_ip = '127.0.0.1'; local_port = 18080; remote_port = 6003; enabled = $true }
    $svcMap = @{ ssh = $ssh; web = $web }

    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services $svcMap -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'h' -Services $svcMap -Transport 'tcp' | Out-Null

    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    try { $changed = Invoke-FrpReconcileReleasedServices }
    finally { Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue }
    Assert-FrpTrue ([bool]$changed) 'reconcile reports a change'
    $map = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue ($map.Contains('ssh')) 'ssh kept'
    Assert-FrpTrue (-not $map.Contains('web')) 'web dropped after release'
    $tomlAfter = [System.IO.File]::ReadAllText((Get-FrpTomlPath))
    Assert-FrpTrue ($tomlAfter -notmatch 'remotePort = 6003') 'toml no longer has web proxy'
    Assert-FrpTrue ($tomlAfter -match 'remotePort = 6002') 'toml still has ssh'

    $webDisabled = @{ id = 'web'; name = 'Web'; preset = 'custom'; local_ip = '127.0.0.1'; local_port = 18080; remote_port = 6003; enabled = $false }
    $svcMap2 = @{ ssh = $ssh; web = $webDisabled }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services $svcMap2 -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh","web"]'
    try { $changed2 = Invoke-FrpReconcileReleasedServices }
    finally { Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue }
    Assert-FrpTrue (-not $changed2) 'no change when registry still lists disabled web'
    $map2 = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue ($map2.Contains('web')) 'disabled reserved web kept'

    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services @{ ssh = $ssh } -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'h' -Services @{ ssh = $ssh } -Transport 'tcp' | Out-Null
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '[]'
    try { $changed3 = Invoke-FrpReconcileReleasedServices }
    finally { Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue }
    Assert-FrpTrue ([bool]$changed3) 'last service release changes state'
    Assert-FrpEqual 'management_only' (Get-FrpInstallStatus) 'management_only after last release'
    $map3 = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpEqual 0 $map3.Count 'no local services after last release'
    $tomlEmpty = [System.IO.File]::ReadAllText((Get-FrpTomlPath))
    Assert-FrpTrue ($tomlEmpty -notmatch '\[\[proxies\]\]') 'no ghost proxies in toml'

    Write-FrpTestPass 'test-reconcile-release'
} finally {
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
