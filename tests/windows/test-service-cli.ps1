# test-service-cli.ps1 — FrpClient.ps1 list/add-service/set-service/enable-service/
# disable-service/discard entrypoints (subprocess, no network involved).
. (Join-Path $PSScriptRoot 'common.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-svc-cli-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
$env:FRP_WINDOWS_ROOT = $tmpRoot
try {
    # Seed an enrolled client-state.json directly via the lib (no network).
    . (Join-Path $script:WindowsLib 'FrpPaths.ps1')
    . (Join-Path $script:WindowsLib 'FrpCrypto.ps1')
    . (Join-Path $script:WindowsLib 'FrpState.ps1')
    Initialize-FrpDirectories
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-cli' -MachineId $mid -HostId 'cliabcd' `
        -Services @{ rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60040; enabled = $true } } `
        -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    $listOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath list 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'list exits 0'
    Assert-FrpTrue ($listOut -match 'rdp') 'list shows rdp'
    Assert-FrpTrue ($listOut -match 'enabled') 'list shows state'

    $addOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath add-service -Preset custom -Id web -Name Web -TargetHost 10.0.0.5 -TargetPort 8080 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'add-service exits 0'
    Assert-FrpTrue ($addOut -match 'Pending service web added') 'add-service message'
    Assert-FrpTrue (Test-Path -LiteralPath (Join-Path (Join-Path $tmpRoot 'state') 'client-draft.json')) 'draft file created on disk'

    $dupOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath add-service -Preset custom -Id web -TargetPort 9090 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -ne 0) 'duplicate add-service fails'
    Assert-FrpTrue ($dupOut -match 'duplicate service id') 'duplicate add-service message'

    $setOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath set-service web target-port 8081 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'set-service exits 0'
    Assert-FrpTrue ($setOut -match 'updated') 'set-service message'

    $disableOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath disable-service web 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'disable-service exits 0'
    Assert-FrpTrue ($disableOut -match 'disabled') 'disable-service message'

    $enableOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath enable-service web 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'enable-service exits 0'
    Assert-FrpTrue ($enableOut -match 'enabled') 'enable-service message'

    & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath disable-service rdp 2>&1 | Out-String | Out-Null
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'disable rdp succeeds while web is still enabled'
    $webDisableOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath disable-service web 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'last enabled service may be disabled (management-only)'
    Assert-FrpTrue ($webDisableOut -match 'disabled') 'disable last service message'

    $discardOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath discard 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'discard exits 0'
    Assert-FrpTrue ($discardOut -match 'discarded') 'discard message'
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Join-Path (Join-Path $tmpRoot 'state') 'client-draft.json'))) 'draft removed from disk'

    Write-FrpTestPass 'test-service-cli'
} finally {
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
