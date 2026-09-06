# FrpAutostart.ps1 — product-owned autostart so frpc survives reboot without
# an interactive login. Windows: a Scheduled Task (SYSTEM, ONSTART trigger)
# running the persisted product CLI wrapper's `start` action. Distinct from
# (and never reuses) any E2E reverse-SSH scheduled task.
#
# Non-Windows test hosts: a JSON marker file under state/ stands in for the
# real scheduler so draft/CRUD-style unit tests can exercise
# register/query/remove without requiring schtasks.exe.

if ((Test-Path variable:script:FrpAutostartLoaded) -and $script:FrpAutostartLoaded) { return }
$script:FrpAutostartLoaded = $true

function Get-FrpAutostartTaskName {
    if ($env:FRP_AUTOSTART_TASK_NAME -and $env:FRP_AUTOSTART_TASK_NAME.Trim().Length -gt 0) {
        return $env:FRP_AUTOSTART_TASK_NAME.Trim()
    }
    return 'FRPAutoDeployClient'
}

function Get-FrpAutostartRunCommand {
    <#
    .SYNOPSIS
      Command line the scheduled task runs at startup: the persisted product
      CLI wrapper's start action (ProgramData install, not the temp
      bootstrap tree, so it works after that tree is removed).
    #>
    $cmdPath = Join-Path (Get-FrpToolsDir) 'frp-client.cmd'
    return ('{0} start' -f $cmdPath)
}

function Get-FrpAutostartMarkerPath {
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    Join-Path (Get-FrpStateDir) ("autostart-task.$TaskName.json")
}

function Invoke-FrpSchtasks {
    <#
    .SYNOPSIS
      Run schtasks.exe with a single pre-quoted argument string (avoids
      Start-Process array-argument re-quoting pitfalls around /TR values
      that themselves contain spaces). Returns the process exit code.
    #>
    param([Parameter(Mandatory = $true)][string]$ArgString)
    $out = [System.IO.Path]::GetTempFileName()
    $err = [System.IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath 'schtasks.exe' -ArgumentList $ArgString -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $out -RedirectStandardError $err
        $detail = ''
        try { $detail = (Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue) } catch { }
        return @{ ExitCode = [int]$p.ExitCode; Detail = $detail }
    } finally {
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $err -Force -ErrorAction SilentlyContinue
    }
}

function Install-FrpAutostartTask {
    <#
    .SYNOPSIS
      Register (or idempotently overwrite) a Scheduled Task that runs
      `frp-client start` as SYSTEM at system startup. No user login required.
    #>
    param(
        [string]$TaskName = (Get-FrpAutostartTaskName),
        [string]$RunCommand
    )
    if (-not $RunCommand) { $RunCommand = Get-FrpAutostartRunCommand }
    if ($env:FRP_WINDOWS_FAIL_AUTOSTART -eq '1') {
        throw 'ERROR: simulated autostart failure (FRP_WINDOWS_FAIL_AUTOSTART=1)'
    }
    Initialize-FrpDirectories

    if (Test-FrpIsWindowsHost) {
        $argString = '/Create /F /RU SYSTEM /RL HIGHEST /SC ONSTART /TN "{0}" /TR "{1}"' -f $TaskName, $RunCommand
        $result = Invoke-FrpSchtasks -ArgString $argString
        if ($result.ExitCode -ne 0) {
            throw ("ERROR: failed to register autostart task (schtasks exit {0}): {1}" -f $result.ExitCode, $result.Detail)
        }
        return $true
    }

    $marker = Get-FrpAutostartMarkerPath -TaskName $TaskName
    $payload = [ordered]@{
        task_name     = $TaskName
        run           = $RunCommand
        run_as        = 'SYSTEM'
        run_level     = 'HIGHEST'
        trigger       = 'ONSTART'
        registered_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $tmp = "$marker.tmp"
    ($payload | ConvertTo-Json) | Set-Content -LiteralPath $tmp
    Move-Item -LiteralPath $tmp -Destination $marker -Force
    return $true
}

function Test-FrpAutostartTaskExists {
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    if (Test-FrpIsWindowsHost) {
        $argString = '/Query /TN "{0}"' -f $TaskName
        $result = Invoke-FrpSchtasks -ArgString $argString
        return ($result.ExitCode -eq 0)
    }
    return (Test-Path -LiteralPath (Get-FrpAutostartMarkerPath -TaskName $TaskName))
}

function Uninstall-FrpAutostartTask {
    <#
    .SYNOPSIS
      Remove the product autostart task. Idempotent: a missing task counts
      as success (used by uninstall, which must not fail if never enabled).
    #>
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    if ($env:FRP_WINDOWS_FAIL_AUTOSTART -eq '1') {
        throw 'ERROR: simulated autostart failure (FRP_WINDOWS_FAIL_AUTOSTART=1)'
    }
    if (Test-FrpIsWindowsHost) {
        if (-not (Test-FrpAutostartTaskExists -TaskName $TaskName)) { return $true }
        $argString = '/Delete /F /TN "{0}"' -f $TaskName
        $result = Invoke-FrpSchtasks -ArgString $argString
        if ($result.ExitCode -ne 0) {
            throw ("ERROR: failed to remove autostart task (schtasks exit {0}): {1}" -f $result.ExitCode, $result.Detail)
        }
        return $true
    }
    $marker = Get-FrpAutostartMarkerPath -TaskName $TaskName
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    return $true
}
