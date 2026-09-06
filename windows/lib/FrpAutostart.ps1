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
      Path of the persisted product CLI wrapper. Arguments are supplied
      separately so schtasks does not mis-parse "cmd start".
    #>
    return (Join-Path (Get-FrpToolsDir) 'frp-client.cmd')
}

function Get-FrpAutostartRunArguments {
    return 'start'
}

function Get-FrpAutostartMarkerPath {
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    Join-Path (Get-FrpStateDir) ("autostart-task.$TaskName.json")
}

function New-FrpAutostartTaskXml {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [int]$DelaySeconds = 30
    )
    $delay = 'PT{0}S' -f [Math]::Max(0, [int]$DelaySeconds)
    $cmdEsc = [System.Security.SecurityElement]::Escape($Command)
    $argEsc = [System.Security.SecurityElement]::Escape($Arguments)
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>FRP Auto Deploy client runtime autostart (product-owned). Starts frpc at boot as SYSTEM.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>$delay</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$cmdEsc</Command>
      <Arguments>$argEsc</Arguments>
    </Exec>
  </Actions>
</Task>
"@
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
        [string]$RunCommand,
        [string]$RunArguments
    )
    if (-not $RunCommand) { $RunCommand = Get-FrpAutostartRunCommand }
    if (-not $RunArguments) { $RunArguments = Get-FrpAutostartRunArguments }
    if ($env:FRP_WINDOWS_FAIL_AUTOSTART -eq '1') {
        throw 'ERROR: simulated autostart failure (FRP_WINDOWS_FAIL_AUTOSTART=1)'
    }
    Initialize-FrpDirectories

    if (Test-FrpIsWindowsHost) {
        # End a stuck prior instance so /Create can replace cleanly.
        $null = Invoke-FrpSchtasks -ArgString ('/End /TN "{0}"' -f $TaskName)
        $xml = New-FrpAutostartTaskXml -Command $RunCommand -Arguments $RunArguments
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("frp-autostart-" + [guid]::NewGuid().ToString('N') + '.xml')
        try {
            Set-Content -LiteralPath $tmp -Value $xml -Encoding Unicode
            $argString = '/Create /F /TN "{0}" /XML "{1}"' -f $TaskName, $tmp
            $result = Invoke-FrpSchtasks -ArgString $argString
            if ($result.ExitCode -ne 0) {
                throw ("ERROR: failed to register autostart task (schtasks exit {0}): {1}" -f $result.ExitCode, $result.Detail)
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
        return $true
    }

    $marker = Get-FrpAutostartMarkerPath -TaskName $TaskName
    $payload = [ordered]@{
        task_name     = $TaskName
        run           = ("{0} {1}" -f $RunCommand, $RunArguments).Trim()
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
