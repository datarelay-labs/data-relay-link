# FrpProcess.ps1 — start/stop/status for project-managed frpc.

if ((Test-Path variable:script:FrpProcessLoaded) -and $script:FrpProcessLoaded) { return }
$script:FrpProcessLoaded = $true

function Read-FrpPidMetadata {
    $path = Get-FrpPidPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $raw = ([System.IO.File]::ReadAllText($path)).Trim()
    if (-not $raw) { return $null }
    # Legacy bare PID
    $pidVal = 0
    if ([int]::TryParse($raw, [ref]$pidVal)) {
        if ($pidVal -le 0) { return $null }
        return [pscustomobject]@{
            pid        = $pidVal
            exe        = $null
            started_at = $null
        }
    }
    try {
        $obj = $raw | ConvertFrom-Json
    } catch {
        return $null
    }
    $pidVal = 0
    if (-not [int]::TryParse([string]$obj.pid, [ref]$pidVal) -or $pidVal -le 0) { return $null }
    return [pscustomobject]@{
        pid        = $pidVal
        exe        = $(if ($obj.exe) { [string]$obj.exe } else { $null })
        started_at = $(if ($obj.started_at) { [string]$obj.started_at } else { $null })
    }
}

function Read-FrpPidFile {
    $meta = Read-FrpPidMetadata
    if ($null -eq $meta) { return $null }
    return [int]$meta.pid
}

function Write-FrpPidFile {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [string]$ExePath
    )
    Initialize-FrpDirectories
    $path = Get-FrpPidPath
    $tmp = "$path.tmp"
    if (-not $ExePath) { $ExePath = Get-FrpFrpcPath }
    $meta = [ordered]@{
        pid        = [int]$ProcessId
        exe        = [string]$ExePath
        started_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $json = ($meta | ConvertTo-Json -Compress)
    [System.IO.File]::WriteAllText($tmp, $json + "`n")
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Clear-FrpPidFile {
    $path = Get-FrpPidPath
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Test-FrpProcessOwned {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [string]$ExpectedExe
    )
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        return $false
    }
    if (-not $ExpectedExe) { $ExpectedExe = Get-FrpFrpcPath }
    $expectedLeaf = [System.IO.Path]::GetFileName($ExpectedExe)
    $expectedBase = [System.IO.Path]::GetFileNameWithoutExtension($ExpectedExe)
    $path = $null
    try { $path = $p.Path } catch { $path = $null }

    # Fake-process tests (Linux CI sleep surrogate) may expose a Path that is
    # not the recorded ExpectedExe; allow only under explicit test env.
    if ($env:FRP_WINDOWS_ALLOW_FAKE_PROCESS -eq '1') {
        if ($expectedBase -ieq 'sleep' -or $expectedLeaf -ieq 'sleep' -or $expectedLeaf -ieq 'sleep.exe') {
            if ($p.ProcessName -ieq 'sleep') { return $true }
        }
    }

    if ($path) {
        # Prefer canonical absolute-path match when the OS exposes Path.
        # Same basename at a different path is NOT owned (PID reuse / unrelated install).
        try {
            if ([System.IO.Path]::GetFullPath($path) -ieq [System.IO.Path]::GetFullPath($ExpectedExe)) {
                return $true
            }
        } catch { }
        return $false
    }
    # Path unavailable (some hosts): fall back to process name
    if ($p.ProcessName -ieq $expectedBase -or $p.ProcessName -ieq $expectedLeaf) { return $true }
    return $false
}

function Test-FrpProcessAlive {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [switch]$ValidateOwnership,
        [string]$ExpectedExe
    )
    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        return $false
    }
    if ($ValidateOwnership) {
        if (-not $ExpectedExe) {
            $meta = Read-FrpPidMetadata
            if ($meta -and [int]$meta.pid -eq [int]$ProcessId -and $meta.exe) {
                $ExpectedExe = [string]$meta.exe
            }
        }
        return (Test-FrpProcessOwned -ProcessId $ProcessId -ExpectedExe $ExpectedExe)
    }
    return $true
}

function Clear-FrpStalePid {
    $meta = Read-FrpPidMetadata
    if ($null -eq $meta) { return }
    $pidVal = [int]$meta.pid
    $exe = $meta.exe
    if (-not (Test-FrpProcessAlive -ProcessId $pidVal)) {
        Clear-FrpPidFile
        return
    }
    if (-not (Test-FrpProcessOwned -ProcessId $pidVal -ExpectedExe $exe)) {
        # Stale / mismatched ownership: clear metadata, do NOT kill
        Clear-FrpPidFile
    }
}

function Start-FrpClient {
    <#
    .SYNOPSIS
      Start frpc in the background from existing config. No re-enroll.
    #>
    param(
        [switch]$Force
    )
    Initialize-FrpDirectories
    Clear-FrpStalePid

    if (-not (Test-Path -LiteralPath (Get-FrpTomlPath))) {
        throw 'ERROR: frpc.toml is missing; enroll this client first (install-client.ps1 -ZeroTouch ...)'
    }
    if (-not (Test-Path -LiteralPath (Get-FrpFrpcPath))) {
        throw 'ERROR: frpc.exe is missing; run update or reinstall'
    }

    $existingMeta = Read-FrpPidMetadata
    if ($null -ne $existingMeta) {
        $existing = [int]$existingMeta.pid
        if (Test-FrpProcessAlive -ProcessId $existing -ValidateOwnership -ExpectedExe $existingMeta.exe) {
            if (-not $Force) {
                Write-Host ("frpc already running (pid {0})" -f $existing)
                return $existing
            }
            Stop-FrpClient | Out-Null
        } else {
            Clear-FrpPidFile
        }
    }

    if (-not (Test-FrpIsWindowsHost)) {
        # Linux CI: spawn a disposable sleep process so stop won't kill the test host.
        if ($env:FRP_WINDOWS_ALLOW_FAKE_PROCESS -eq '1') {
            $sleepBin = $null
            foreach ($c in @('sleep', '/bin/sleep')) {
                if (Get-Command $c -ErrorAction SilentlyContinue) { $sleepBin = $c; break }
                if (Test-Path -LiteralPath $c) { $sleepBin = $c; break }
            }
            if (-not $sleepBin) { throw 'ERROR: sleep not available for fake process test' }
            $fake = Start-Process -FilePath $sleepBin -ArgumentList @('120') -PassThru -NoNewWindow
            Write-FrpPidFile -ProcessId $fake.Id -ExePath $sleepBin
            Write-Host ("frpc fake-started under test pid {0}" -f $fake.Id)
            return $fake.Id
        }
        throw 'ERROR: starting frpc.exe requires Windows (or set FRP_WINDOWS_ALLOW_FAKE_PROCESS=1 for tests)'
    }

    $frpc = Get-FrpFrpcPath
    $toml = Get-FrpTomlPath
    # Win32_Process.Create starts outside the OpenSSH/WinRM job object, so
    # frpc keeps running after the install/start session disconnects.
    # Start-Process from an SSH session is killed with that session.
    $cmd = '"{0}" -c "{1}"' -f $frpc, $toml
    $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = $cmd
        CurrentDirectory = [System.IO.Path]::GetDirectoryName($frpc)
    }
    if ($null -eq $created -or [int]$created.ReturnValue -ne 0 -or [int]$created.ProcessId -le 0) {
        throw ('ERROR: failed to start frpc (Win32_Process.Create rc={0})' -f $(if ($created) { $created.ReturnValue } else { 'null' }))
    }
    $procId = [int]$created.ProcessId
    Write-FrpPidFile -ProcessId $procId -ExePath $frpc
    Start-Sleep -Milliseconds 400
    if (-not (Test-FrpProcessAlive -ProcessId $procId -ValidateOwnership -ExpectedExe $frpc)) {
        Clear-FrpPidFile
        throw 'ERROR: frpc exited immediately; check logs\frpc.log'
    }
    Write-Host ("frpc started (pid {0})" -f $procId)
    return $procId
}

function Stop-FrpClient {
    $meta = Read-FrpPidMetadata
    if ($null -eq $meta) {
        Write-Host 'frpc is not running'
        return $false
    }
    $pidVal = [int]$meta.pid
    $exe = $meta.exe
    if (-not (Test-FrpProcessAlive -ProcessId $pidVal)) {
        Clear-FrpPidFile
        Write-Host 'frpc is not running (cleared stale pid)'
        return $false
    }
    if (-not (Test-FrpProcessOwned -ProcessId $pidVal -ExpectedExe $exe)) {
        Clear-FrpPidFile
        Write-Host 'frpc pid metadata mismatched; cleared without killing unrelated process'
        return $false
    }
    # Kill only the project-managed frpc matching recorded exe path/name.
    try {
        Stop-Process -Id $pidVal -Force -ErrorAction Stop
    } catch {
        throw ("ERROR: failed to stop frpc pid {0}" -f $pidVal)
    }
    Clear-FrpPidFile
    Write-Host ("frpc stopped (pid {0})" -f $pidVal)
    return $true
}

function Get-FrpClientStatus {
    Clear-FrpStalePid
    $meta = Read-FrpPidMetadata
    $pidVal = $(if ($meta) { [int]$meta.pid } else { $null })
    $running = $false
    if ($null -ne $pidVal -and (Test-FrpProcessAlive -ProcessId $pidVal -ValidateOwnership -ExpectedExe $(if ($meta) { $meta.exe } else { $null }))) {
        $running = $true
    }
    $enrolled = Test-FrpIsEnrolled
    $state = $null
    if (Test-Path -LiteralPath (Get-FrpStatePath)) {
        try { $state = Read-FrpClientState } catch { }
    }
    return [pscustomobject]@{
        Running   = $running
        Pid       = $pidVal
        Enrolled  = $enrolled
        StatePath = (Get-FrpStatePath)
        TomlPath  = (Get-FrpTomlPath)
        FrpcPath  = (Get-FrpFrpcPath)
        Server    = $(if ($state) { $state.frp_server } else { $null })
        Transport = $(if ($state) { $state.frp_transport } else { $null })
    }
}
