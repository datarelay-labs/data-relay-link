# test-canonical-cli.ps1 — Windows resource-first drlink grammar + update modes.
. (Join-Path $PSScriptRoot 'common.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-canon-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
$env:FRP_WINDOWS_ROOT = $tmpRoot
try {
    . (Join-Path $script:WindowsLib 'FrpPaths.ps1')
    . (Join-Path $script:WindowsLib 'FrpCrypto.ps1')
    . (Join-Path $script:WindowsLib 'FrpState.ps1')
    Initialize-FrpDirectories
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-cli' -MachineId $mid -HostId 'cliabcd' `
        -Services @{ rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60040; enabled = $true } } `
        -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    $help = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath help 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'help exits 0'
    Assert-FrpTrue ($help -match 'service list') 'help advertises service list'
    Assert-FrpTrue ($help -match 'client info') 'help advertises client info'
    Assert-FrpTrue ($help -match 'update project') 'help advertises update project'
    Assert-FrpTrue ($help -match 'update engine') 'help advertises update engine'
    Assert-FrpTrue ($help -notmatch 'add-service') 'help hides legacy add-service'

    $list = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath service list 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'service list exits 0'
    Assert-FrpTrue ($list -match 'rdp') 'service list shows rdp'

    $info = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath client info 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'client info exits 0'

    $add = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath service add `
        -Preset custom -Id web -Name Web -TargetHost 10.0.0.5 -TargetPort 8080 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'service add exits 0'
    Assert-FrpTrue ($add -match 'Pending service web added') 'service add message'

    $check = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath update -Check 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'update --check exits 0'
    Assert-FrpTrue ($check -match 'Data Relay Link project') 'check shows project section'
    Assert-FrpTrue ($check -match 'FRP engine') 'check shows engine section'

    $bad = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath client nope 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -ne 0) 'bad client subcommand fails'

    Write-FrpTestPass 'test-canonical-cli'
} finally {
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
