# test-client-lock.ps1 — Windows client mutation lock
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60030; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    Assert-FrpTrue (Enter-FrpClientLock) 'acquire lock'
    Assert-FrpTrue (Enter-FrpClientLock) 'reentrant same process'
    Exit-FrpClientLock
    Exit-FrpClientLock
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Get-FrpClientLockPath))) 'released'

    $lock = Get-FrpClientLockPath
    New-Item -ItemType Directory -Path $lock -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $lock 'pid') -Value ([string]$PID)
    Assert-FrpTrue (-not (Enter-FrpClientLock)) 'live holder without depth blocks'

    $addOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath add-service -Preset custom -Id web -TargetPort 8080 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -ne 0) 'add-service fails when lock held'
    Assert-FrpTrue ($addOut -match 'already running') 'add-service reports lock contention'

    $statusOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath status 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) ("status remains usable while lock is held: $statusOut")
    Assert-FrpTrue ($statusOut -match '(?i)enrolled=') ("status output while lock held: $statusOut")
    Remove-Item -LiteralPath $lock -Recurse -Force

    New-Item -ItemType Directory -Path $lock -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $lock 'pid') -Value '999999'
    Assert-FrpTrue (Enter-FrpClientLock) 'stale pid reclaimed'
    Exit-FrpClientLock

    Write-FrpTestPass 'test-client-lock'
} finally {
    try { Exit-FrpClientLock } catch { }
    Remove-FrpWindowsTestRoot
}
