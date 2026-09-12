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
    return 'DataRelayLinkClient'
}

function Get-FrpAutostartLegacyTaskName {
    <#
    .SYNOPSIS
      Historical Scheduled Task name from pre-DataRelay branding.
    #>
    return 'FRPAutoDeployClient'
}

function Get-FrpAutostartLegacyTaskNames {
    <#
    .SYNOPSIS
      Older product task names that may still exist after branding renames.
      Migration removes them only when ownership validation passes.
    #>
    return @((Get-FrpAutostartLegacyTaskName))
}

function Test-FrpAutostartTaskProductOwned {
    <#
    .SYNOPSIS
      True when an existing task is product-owned (SYSTEM + BootTrigger +
      product autostart wrapper). Never touch unrelated admin tasks.
    #>
    param([Parameter(Mandatory = $true)][string]$TaskName)
    if (-not (Test-FrpAutostartTaskExists -TaskName $TaskName)) { return $false }
    return (Test-FrpAutostartHealthy -TaskName $TaskName)
}

function Move-FrpAutostartLegacyTaskIfPresent {
    <#
    .SYNOPSIS
      If the legacy FRPAutoDeployClient task exists and is product-owned,
      remove it so Install can create DataRelayLinkClient. Unrelated tasks
      with that name are left untouched.
    #>
    $legacy = Get-FrpAutostartLegacyTaskName
    $canonical = Get-FrpAutostartTaskName
    if ($legacy -eq $canonical) { return $false }
    if (-not (Test-FrpAutostartTaskExists -TaskName $legacy)) { return $false }
    if (-not (Test-FrpAutostartTaskProductOwned -TaskName $legacy)) {
        Write-Warning ("Leaving non-product Scheduled Task '{0}' untouched." -f $legacy)
        return $false
    }
    Uninstall-FrpAutostartTask -TaskName $legacy
    return $true
}

function Get-FrpAutostartRunCommand {
    <#
    .SYNOPSIS
      Path of the product boot wrapper. Uses a redirected cmd entrypoint so
      PowerShell Write-Host cannot hang when the SYSTEM task has no console.
    #>
    return (Join-Path (Get-FrpToolsDir) 'frp-autostart.cmd')
}

function Get-FrpAutostartRunArguments {
    return ''
}

function Get-FrpAutostartMarkerPath {
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    Join-Path (Get-FrpStateDir) ("autostart-task.$TaskName.json")
}

function New-FrpAutostartTaskXml {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [AllowEmptyString()][string]$Arguments = '',
        [int]$DelaySeconds = 30
    )
    $delay = 'PT{0}S' -f [Math]::Max(0, [int]$DelaySeconds)
    $cmdEsc = [System.Security.SecurityElement]::Escape($Command)
    $argEsc = [System.Security.SecurityElement]::Escape([string]$Arguments)
    $argElement = if ([string]::IsNullOrWhiteSpace($Arguments)) {
        ''
    } else {
        "      <Arguments>$argEsc</Arguments>`n"
    }
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Data Relay Link client runtime autostart (product-owned). Starts frpc at boot as SYSTEM.</Description>
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
$argElement    </Exec>
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
        $output = ''
        try { $detail = (Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue) } catch { }
        try { $output = (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) } catch { }
        return @{ ExitCode = [int]$p.ExitCode; Detail = $detail; Output = $output }
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

    # Prefer canonical DataRelayLinkClient; migrate product-owned legacy name.
    $null = Move-FrpAutostartLegacyTaskIfPresent

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
        if (-not (Test-FrpAutostartHealthy -TaskName $TaskName)) {
            throw 'ERROR: autostart task exists but is not a SYSTEM boot task at the installed product path'
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
    if (-not (Test-FrpAutostartHealthy -TaskName $TaskName)) {
        throw 'ERROR: autostart task exists but is not a SYSTEM boot task at the installed product path'
    }
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

function Test-FrpAutostartHealthy {
    <#
    .SYNOPSIS
      True only when the product autostart task exists, runs as SYSTEM, has a
      boot trigger, and invokes the installed frp-autostart.cmd wrapper.
    #>
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    if (-not (Test-FrpAutostartTaskExists -TaskName $TaskName)) { return $false }
    $expectedCmd = Get-FrpAutostartRunCommand
    if (Test-FrpIsWindowsHost) {
        $result = Invoke-FrpSchtasks -ArgString ('/Query /TN "{0}" /XML' -f $TaskName)
        if ($result.ExitCode -ne 0) { return $false }
        $xml = [string]$result.Output
        if ($xml -notmatch 'S-1-5-18') { return $false }
        if ($xml -notmatch 'BootTrigger') { return $false }
        $cmdEsc = [System.Security.SecurityElement]::Escape($expectedCmd)
        if ($xml -notmatch [regex]::Escape($expectedCmd) -and ($cmdEsc -and $xml -notmatch [regex]::Escape($cmdEsc))) {
            return $false
        }
        return $true
    }
    $markerPath = Get-FrpAutostartMarkerPath -TaskName $TaskName
    try {
        $raw = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        return $false
    }
    if ([string]$raw.run_as -ne 'SYSTEM') { return $false }
    if ([string]$raw.trigger -ne 'ONSTART') { return $false }
    $run = [string]$raw.run
    if (-not $run -or $run -notmatch [regex]::Escape($expectedCmd)) { return $false }
    return $true
}

function Uninstall-FrpAutostartTask {
    <#
    .SYNOPSIS
      Remove the product autostart task. Idempotent: a missing task counts
      as success (used by uninstall, which must not fail if never enabled).
      Also removes product-owned legacy task names when present.
    #>
    param([string]$TaskName = (Get-FrpAutostartTaskName))
    if ($env:FRP_WINDOWS_FAIL_AUTOSTART -eq '1') {
        throw 'ERROR: simulated autostart failure (FRP_WINDOWS_FAIL_AUTOSTART=1)'
    }
    $names = New-Object System.Collections.Generic.List[string]
    [void]$names.Add($TaskName)
    foreach ($legacy in (Get-FrpAutostartLegacyTaskNames)) {
        if ($legacy -ne $TaskName) { [void]$names.Add($legacy) }
    }
    foreach ($name in $names) {
        if (Test-FrpIsWindowsHost) {
            if (-not (Test-FrpAutostartTaskExists -TaskName $name)) { continue }
            # Only delete when ownership validation passes (or marker path on
            # non-Windows). Legacy names that are not product-owned are left alone.
            if ($name -ne $TaskName -and -not (Test-FrpAutostartHealthy -TaskName $name)) {
                continue
            }
            $argString = '/Delete /F /TN "{0}"' -f $name
            $result = Invoke-FrpSchtasks -ArgString $argString
            if ($result.ExitCode -ne 0) {
                throw ("ERROR: failed to remove autostart task (schtasks exit {0}): {1}" -f $result.ExitCode, $result.Detail)
            }
            if (Test-FrpAutostartTaskExists -TaskName $name) {
                throw 'ERROR: autostart task still present after removal'
            }
            continue
        }
        $marker = Get-FrpAutostartMarkerPath -TaskName $name
        if ($name -ne $TaskName -and (Test-Path -LiteralPath $marker)) {
            if (-not (Test-FrpAutostartHealthy -TaskName $name)) { continue }
        }
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
        if (Test-FrpAutostartTaskExists -TaskName $name) {
            throw 'ERROR: autostart task still present after removal'
        }
    }
    return $true
}
