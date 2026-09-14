# FrpShim.ps1 — make the documented bare `drlink` command resolvable from any
# new shell after install, and remove only what the product added on uninstall.
#
# The product CLI lives at %ProgramData%\drlink\tools\drlink.cmd. Install adds
# that directory to the machine PATH (appended, never prepended, so an
# unrelated `drlink` already on PATH keeps precedence) and records exactly what
# it changed in state\path-shim.json. Uninstall consults that record and
# removes the entry only when the product added it.
#
# Non-Windows test hosts simulate the machine PATH in a file under the test
# root so the install/uninstall/ownership logic is exercised off Windows.

if ((Test-Path variable:script:FrpShimLoaded) -and $script:FrpShimLoaded) { return }
$script:FrpShimLoaded = $true

function Get-FrpShimCommandName { 'drlink' }

function Get-FrpShimFileName { 'drlink.cmd' }

function Get-FrpShimPath { Join-Path (Get-FrpToolsDir) (Get-FrpShimFileName) }

function Get-FrpShimMarkerPath { Join-Path (Get-FrpStateDir) 'path-shim.json' }

function Get-FrpShimOwnershipMarker { 'DRLINK-PRODUCT-SHIM' }

function Get-FrpSimulatedMachinePathFile {
    if ($env:FRP_WINDOWS_FAKE_MACHINE_PATH -and $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim().Length -gt 0) {
        return $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim()
    }
    return (Join-Path (Get-FrpStateDir) 'machine-path.simulated')
}

function Get-FrpMachinePathValue {
    # Tests set FRP_WINDOWS_FAKE_MACHINE_PATH so install/uninstall logic can be
    # exercised without mutating the real machine PATH — including on Windows.
    if ($env:FRP_WINDOWS_FAKE_MACHINE_PATH -and $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim().Length -gt 0) {
        $file = $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim()
        if (Test-Path -LiteralPath $file) {
            return ([System.IO.File]::ReadAllText($file)).Trim()
        }
        return ''
    }
    if (Test-FrpIsWindowsHost) {
        try {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            $item = Get-Item -LiteralPath $key -ErrorAction Stop
            return [string]$item.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        } catch {
            return [string][Environment]::GetEnvironmentVariable('Path', 'Machine')
        }
    }
    $file = Get-FrpSimulatedMachinePathFile
    if (Test-Path -LiteralPath $file) {
        return ([System.IO.File]::ReadAllText($file)).Trim()
    }
    return ''
}

function Set-FrpMachinePathValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($env:FRP_WINDOWS_FAIL_PATH_SHIM -eq '1') {
        throw 'ERROR: simulated machine PATH update failure (FRP_WINDOWS_FAIL_PATH_SHIM=1)'
    }
    if ($env:FRP_WINDOWS_FAKE_MACHINE_PATH -and $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim().Length -gt 0) {
        $file = $env:FRP_WINDOWS_FAKE_MACHINE_PATH.Trim()
        $dir = Split-Path -Parent $file
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::WriteAllText($file, $Value + "`n")
        return $Value
    }
    if (Test-FrpIsWindowsHost) {
        # Write through the registry so a REG_EXPAND_SZ Path keeps its type and
        # %SystemRoot%-style entries are not flattened.
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        $kind = 'ExpandString'
        try { $kind = (Get-Item -LiteralPath $key).GetValueKind('Path') } catch { $kind = 'ExpandString' }
        Set-ItemProperty -LiteralPath $key -Name 'Path' -Value $Value -Type $kind
        Publish-FrpEnvironmentChange
        return $Value
    }
    $file = Get-FrpSimulatedMachinePathFile
    $dir = Split-Path -Parent $file
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($file, $Value + "`n")
    return $Value
}

function Publish-FrpEnvironmentChange {
    <#
    .SYNOPSIS
      Broadcast WM_SETTINGCHANGE so shells started after install pick up the
      new machine PATH without a reboot.
    #>
    if (-not (Test-FrpIsWindowsHost)) { return $false }
    try {
        if (-not ('FrpEnvBroadcast' -as [type])) {
            Add-Type -Namespace '' -Name 'FrpEnvBroadcast' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@ -ErrorAction Stop
        }
        $result = [UIntPtr]::Zero
        [void][FrpEnvBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [IntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
        return $true
    } catch {
        return $false
    }
}

function Split-FrpPathList {
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if (-not $Value) { return @() }
    return @($Value -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Test-FrpPathEntryEquals {
    param([AllowEmptyString()][string]$Left, [AllowEmptyString()][string]$Right)
    $a = ([string]$Left).Trim().TrimEnd('\', '/')
    $b = ([string]$Right).Trim().TrimEnd('\', '/')
    if (-not $a -or -not $b) { return $false }
    if (Test-FrpIsWindowsHost) {
        try {
            $a = [System.Environment]::ExpandEnvironmentVariables($a)
            $b = [System.Environment]::ExpandEnvironmentVariables($b)
        } catch { }
        return ($a -ieq $b)
    }
    return ($a -eq $b)
}

function Test-FrpShimFileProductOwned {
    <#
    .SYNOPSIS
      True only for a drlink launcher this product wrote (ownership marker in
      the file body). Anything else is somebody else's `drlink`.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $text = [System.IO.File]::ReadAllText($Path)
    } catch {
        return $false
    }
    return ($text -match [regex]::Escape((Get-FrpShimOwnershipMarker)))
}

function Find-FrpCommandOnMachinePath {
    <#
    .SYNOPSIS
      Resolve a command name against the machine PATH the way a brand-new
      shell would (first match wins, PATHEXT order).
    #>
    param([string]$Name = (Get-FrpShimCommandName))
    $extensions = @('.cmd', '.bat', '.exe', '.com', '')
    foreach ($dir in (Split-FrpPathList -Value (Get-FrpMachinePathValue))) {
        $expanded = $dir
        if (Test-FrpIsWindowsHost) {
            try { $expanded = [System.Environment]::ExpandEnvironmentVariables($dir) } catch { }
        }
        foreach ($ext in $extensions) {
            $candidate = Join-Path $expanded ($Name + $ext)
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    return $null
}

function Read-FrpShimMarker {
    $path = Get-FrpShimMarkerPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return ([System.IO.File]::ReadAllText($path) | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Save-FrpShimMarker {
    param(
        [Parameter(Mandatory = $true)][string]$ToolsDir,
        [Parameter(Mandatory = $true)][bool]$PathEntryAdded
    )
    Initialize-FrpDirectories
    $path = Get-FrpShimMarkerPath
    $payload = [ordered]@{
        command          = (Get-FrpShimCommandName)
        shim             = (Get-FrpShimPath)
        tools_dir        = $ToolsDir
        path_entry_added = $PathEntryAdded
        path_scope       = 'Machine'
        installed_at     = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, ($payload | ConvertTo-Json -Depth 4) + "`n")
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return $path
}

function Get-FrpCommandShimStatus {
    $tools = Get-FrpToolsDir
    $shim = Get-FrpShimPath
    $entries = Split-FrpPathList -Value (Get-FrpMachinePathValue)
    $onPath = $false
    foreach ($e in $entries) {
        if (Test-FrpPathEntryEquals -Left $e -Right $tools) { $onPath = $true; break }
    }
    $resolved = Find-FrpCommandOnMachinePath -Name (Get-FrpShimCommandName)
    $productOwned = Test-FrpShimFileProductOwned -Path $resolved
    return [pscustomobject]@{
        ShimPath     = $shim
        ShimPresent  = (Test-Path -LiteralPath $shim)
        ToolsOnPath  = $onPath
        Resolved     = $resolved
        ResolvesToProduct = [bool]$productOwned
        ForeignCommand = $(if ($resolved -and -not $productOwned) { $resolved } else { $null })
        Marker       = (Read-FrpShimMarker)
    }
}

function Test-FrpCommandShimHealthy {
    $status = Get-FrpCommandShimStatus
    return ($status.ShimPresent -and $status.ToolsOnPath -and $status.ResolvesToProduct)
}

function Install-FrpCommandShim {
    <#
    .SYNOPSIS
      Put %ProgramData%\drlink\tools on the machine PATH so `drlink ...` works
      from a fresh shell in any directory. Appends, so an unrelated `drlink`
      already on PATH is never hijacked. Idempotent.
    #>
    param([switch]$Quiet)
    Initialize-FrpDirectories
    $tools = Get-FrpToolsDir
    $shim = Get-FrpShimPath
    if (-not (Test-Path -LiteralPath $shim)) {
        throw ("ERROR: product CLI launcher is missing: {0}" -f $shim)
    }

    $preexisting = Find-FrpCommandOnMachinePath -Name (Get-FrpShimCommandName)
    $foreign = $null
    if ($preexisting -and -not (Test-FrpShimFileProductOwned -Path $preexisting)) {
        $foreign = $preexisting
    }

    $entries = Split-FrpPathList -Value (Get-FrpMachinePathValue)
    $already = $false
    foreach ($e in $entries) {
        if (Test-FrpPathEntryEquals -Left $e -Right $tools) { $already = $true; break }
    }

    $added = $false
    if (-not $already) {
        $newValue = (@($entries) + @($tools)) -join ';'
        Set-FrpMachinePathValue -Value $newValue | Out-Null
        $added = $true
    }

    $marker = Read-FrpShimMarker
    $everAdded = $added
    if (-not $everAdded -and $marker -and $marker.path_entry_added -eq $true) {
        $everAdded = $true
    }
    Save-FrpShimMarker -ToolsDir $tools -PathEntryAdded $everAdded | Out-Null

    if (-not $Quiet) {
        if ($added) {
            Write-Host ("Added {0} to the system PATH: 'drlink' now works in any new shell." -f $tools)
        } else {
            Write-Host ("System PATH already includes {0}: 'drlink' works in any new shell." -f $tools)
        }
        if ($foreign) {
            Write-Host ("NOTE: an unrelated 'drlink' command already exists at {0} and keeps precedence." -f $foreign)
            Write-Host ("      Run this product explicitly as: {0}" -f $shim)
        }
    }
    return [pscustomobject]@{
        ShimPath        = $shim
        PathEntryAdded  = $added
        AlreadyOnPath   = $already
        ForeignCommand  = $foreign
    }
}

function Uninstall-FrpCommandShim {
    <#
    .SYNOPSIS
      Remove the product PATH entry, and only that: an entry the product never
      added (site-managed PATH) and any unrelated `drlink` are left alone.
      Must run before the product root is deleted, while the marker is readable.
    #>
    param([switch]$Quiet)
    $tools = Get-FrpToolsDir
    $marker = Read-FrpShimMarker
    $removed = $false

    if ($null -eq $marker) {
        if (-not $Quiet) {
            Write-Host 'No product PATH entry was recorded; leaving the system PATH unchanged.'
        }
        return [pscustomobject]@{ PathEntryRemoved = $false; Reason = 'no-marker' }
    }
    if ($marker.path_entry_added -ne $true) {
        if (-not $Quiet) {
            Write-Host 'System PATH entry was not added by this product; leaving it unchanged.'
        }
        return [pscustomobject]@{ PathEntryRemoved = $false; Reason = 'not-product-added' }
    }

    $recordedTools = [string]$marker.tools_dir
    if (-not $recordedTools) { $recordedTools = $tools }
    $entries = Split-FrpPathList -Value (Get-FrpMachinePathValue)
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($e in $entries) {
        if (Test-FrpPathEntryEquals -Left $e -Right $recordedTools) {
            $removed = $true
            continue
        }
        [void]$kept.Add($e)
    }
    if ($removed) {
        Set-FrpMachinePathValue -Value (($kept.ToArray()) -join ';') | Out-Null
    }
    Remove-Item -LiteralPath (Get-FrpShimMarkerPath) -Force -ErrorAction SilentlyContinue
    if (-not $Quiet) {
        if ($removed) {
            Write-Host ("Removed {0} from the system PATH." -f $recordedTools)
        } else {
            Write-Host 'Product PATH entry was already absent.'
        }
    }
    return [pscustomobject]@{ PathEntryRemoved = $removed; Reason = 'product-owned' }
}
