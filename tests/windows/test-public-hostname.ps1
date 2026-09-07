# test-public-hostname.ps1 — Windows public_hostname lifecycle parity
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $macKey = New-FrpNonce
    Save-FrpIdentityMac -MacKeyHex $macKey | Out-Null

    $ssh = @{
        id = 'ssh'; name = 'SSH'; preset = 'ssh'; local_ip = '127.0.0.1'
        local_port = 22; remote_port = 6003; enabled = $true; ssh_user = 'leeruda'
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer '203.0.113.10' `
        -FrpServerPort 443 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services @{ ssh = $ssh } -Transport 'tcp' -InstallStatus 'installed' `
        -PublicHostname 'access.example.com' | Out-Null
    New-FrpClientToml -ServerAddr '203.0.113.10' -ServerPort 443 -Token 'tok' `
        -HostId 'h' -Services @{ ssh = $ssh } -Transport 'tcp' | Out-Null

    $state = Read-FrpClientState
    Assert-FrpEqual 'access.example.com' ([string]$state.public_hostname) 'hostname persisted'
    Assert-FrpEqual '203.0.113.10' ([string]$state.frp_server) 'serverAddr unchanged after persist'
    $toml = [System.IO.File]::ReadAllText((Get-FrpTomlPath))
    Assert-FrpTrue ($toml -match 'serverAddr = "203.0.113.10"') 'toml control endpoint is infrastructure'
    Assert-FrpTrue ($toml -notmatch 'access.example.com') 'toml does not use alias'

    $clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
    $hostExe = 'pwsh'
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
    try {
        $hp = (Get-Process -Id $PID).Path
        if ($hp) { $hostExe = $hp }
    } catch { }
    $infoOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath info 2>&1 | Out-String
    Assert-FrpEqual 0 $LASTEXITCODE 'info exits 0'
    Assert-FrpTrue ($infoOut -match 'Public : access.example.com:6003') 'info preferred public'
    Assert-FrpTrue ($infoOut -match 'Fallback public : 203.0.113.10:6003') 'info fallback public'
    Assert-FrpTrue ($infoOut -match 'ssh -p 6003 leeruda@access.example.com') 'info preferred ssh'
    Assert-FrpTrue ($infoOut -match 'ssh -p 6003 leeruda@203.0.113.10') 'info fallback ssh'

    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT = '1'
    $env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME = 'access2.example.com'
    $changed = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue ([bool]$changed) 'hostname change is a reconcile success'
    Assert-FrpEqual 'access2.example.com' ([string](Read-FrpClientState).public_hostname) 'hostname changed'
    $toml2 = [System.IO.File]::ReadAllText((Get-FrpTomlPath))
    Assert-FrpTrue ($toml2 -match 'serverAddr = "203.0.113.10"') 'change does not mutate serverAddr'
    Assert-FrpEqual 6003 ([int]((ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services)['ssh'].remote_port)) 'public port unchanged'

    $env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME = ''
    $changedClear = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue ([bool]$changedClear) 'explicit clear is a change'
    Assert-FrpTrue (-not (Test-FrpObjectHasProperty -Object (Read-FrpClientState) -Name 'public_hostname') -or [string](Read-FrpClientState).public_hostname -eq '') 'hostname cleared'

    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer '203.0.113.10' `
        -FrpServerPort 443 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services @{ ssh = $ssh } -Transport 'tcp' -InstallStatus 'installed' `
        -PublicHostname 'stale.example.com' | Out-Null
    Remove-Item Env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME -ErrorAction SilentlyContinue
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $noop = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue (-not $noop) 'old-server field absent is no-op for hostname'
    Assert-FrpEqual 'stale.example.com' ([string](Read-FrpClientState).public_hostname) 'old-server preserves hostname'

    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer '203.0.113.10' `
        -FrpServerPort 443 -Hostname 'win' -MachineId $mid -HostId 'h' `
        -Services @{} -Transport 'tcp' -InstallStatus 'management_only' `
        -PublicHostname 'keep.example.com' | Out-Null
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '[]'
    $env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT = '1'
    $env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME = 'zero.example.com'
    $zero = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue ([bool]$zero) 'zero-service hostname sync'
    Assert-FrpEqual 'zero.example.com' ([string](Read-FrpClientState).public_hostname) 'zero-service hostname applied'
    Assert-FrpEqual 0 (ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services).Count 'zero-service remains empty'

    Write-FrpTestPass 'test-public-hostname'
} finally {
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
