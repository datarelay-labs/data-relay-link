# test-autostart-cli.ps1 — FrpClient.ps1 autostart -Enable/-Disable/status,
# and uninstall removes the autostart task (subprocess, marker backend).
. (Join-Path $PSScriptRoot 'common.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

function Test-FrpSchtasksExists {
    param([string]$TaskName)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $null = & schtasks.exe /Query /TN $TaskName 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    return ($rc -eq 0)
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-autostart-cli-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
$env:FRP_WINDOWS_ROOT = $tmpRoot
$env:FRP_AUTOSTART_TASK_NAME = 'FRPAutoDeployClient-Test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$isWin = ($env:OS -match 'Windows' -or $env:WinDir)
try {
    $statusOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'autostart status exits 0'
    Assert-FrpTrue ($statusOut -match 'not configured') 'autostart initially not configured'

    $enableOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart -Enable 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'autostart -Enable exits 0'
    Assert-FrpTrue ($enableOut -match 'Autostart enabled') 'autostart -Enable message'
    Assert-FrpTrue ($enableOut -match 'SYSTEM') 'autostart -Enable documents SYSTEM / no login'

    $markerPath = Join-Path (Join-Path $tmpRoot 'state') ("autostart-task.{0}.json" -f $env:FRP_AUTOSTART_TASK_NAME)
    if ($isWin) {
        Assert-FrpTrue (Test-FrpSchtasksExists -TaskName $env:FRP_AUTOSTART_TASK_NAME) 'autostart task registered with schtasks'
    } else {
        Assert-FrpTrue (Test-Path -LiteralPath $markerPath) 'autostart marker persisted on disk'
    }

    $statusOut2 = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart 2>&1 | Out-String
    Assert-FrpTrue ($statusOut2 -match ('enabled \({0}\)' -f [regex]::Escape($env:FRP_AUTOSTART_TASK_NAME))) 'autostart status shows enabled'

    $bothOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart -Enable -Disable 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -ne 0) '-Enable and -Disable together is rejected'

    $disableOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart -Disable 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'autostart -Disable exits 0'
    Assert-FrpTrue ($disableOut -match 'Autostart disabled') 'autostart -Disable message'
    if ($isWin) {
        Assert-FrpTrue (-not (Test-FrpSchtasksExists -TaskName $env:FRP_AUTOSTART_TASK_NAME)) 'schtasks task removed after -Disable'
    } else {
        Assert-FrpTrue (-not (Test-Path -LiteralPath $markerPath)) 'autostart marker removed on disk'
    }

    # uninstall removes a registered autostart task too.
    & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart -Enable 2>&1 | Out-String | Out-Null
    if ($isWin) {
        Assert-FrpTrue (Test-FrpSchtasksExists -TaskName $env:FRP_AUTOSTART_TASK_NAME) 'autostart re-enabled before uninstall'
    } else {
        Assert-FrpTrue (Test-Path -LiteralPath $markerPath) 'autostart re-enabled before uninstall'
    }
    $uninstallOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath uninstall 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'uninstall exits 0'
    Assert-FrpTrue ($uninstallOut -match 'SERVER RESERVATIONS PRESERVED') 'uninstall message'
    if ($isWin) {
        Assert-FrpTrue (-not (Test-FrpSchtasksExists -TaskName $env:FRP_AUTOSTART_TASK_NAME)) 'schtasks task gone after uninstall'
    } else {
        Assert-FrpTrue (-not (Test-Path -LiteralPath $tmpRoot -PathType Container) -or -not (Test-Path -LiteralPath $markerPath)) 'autostart marker gone after uninstall'
    }
    Assert-FrpTrue ((Get-Content -LiteralPath $clientPath -Raw) -match 'Uninstall-FrpAutostartTask') 'uninstall source calls Uninstall-FrpAutostartTask'

    Write-FrpTestPass 'test-autostart-cli'
} finally {
    try {
        & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath autostart -Disable 2>&1 | Out-Null
    } catch { }
    Remove-Item Env:FRP_AUTOSTART_TASK_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
