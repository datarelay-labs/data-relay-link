# FrpLock.ps1 — local exclusive lock for client state/draft/runtime mutation.
# Same role as Unix frp_acquire_client_lock: serialize add/set/enable/disable,
# apply, discard, sync, update, and uninstall on one host. Read-only commands
# (status/info/list/doctor) must not take this lock.
#
# Directory mkdir lock with PID reclaim. Re-entrant for the same process so
# apply can call internal helpers that also enter the lock.

if ((Test-Path variable:script:FrpLockLoaded) -and $script:FrpLockLoaded) { return }
$script:FrpLockLoaded = $true
$script:FrpClientLockDepth = 0
$script:FrpClientLockOwner = $null
$script:FrpClientLockPath = $null

function Get-FrpClientLockPath {
    Join-Path (Get-FrpStateDir) 'client-manage.lock'
}

function Test-FrpLockPidAlive {
    param([string]$ProcessId)
    if (-not $ProcessId -or $ProcessId -notmatch '^[0-9]+$') { return $false }
    try {
        $null = Get-Process -Id ([int]$ProcessId) -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Enter-FrpClientLock {
    if ($script:FrpClientLockDepth -gt 0 -and [string]$script:FrpClientLockOwner -eq [string]$PID) {
        $script:FrpClientLockDepth++
        return $true
    }
    Initialize-FrpDirectories
    $lock = Get-FrpClientLockPath
    if (Test-Path -LiteralPath $lock) {
        $pidPath = Join-Path $lock 'pid'
        $old = ''
        if (Test-Path -LiteralPath $pidPath) {
            try { $old = ([string](Get-Content -LiteralPath $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1)).Trim() } catch { $old = '' }
        }
        if (Test-FrpLockPidAlive -ProcessId $old) {
            Write-Host 'ERROR: another frp-client management operation is already running.'
            return $false
        }
        Remove-Item -LiteralPath $lock -Recurse -Force -ErrorAction SilentlyContinue
    }
    try {
        New-Item -ItemType Directory -Path $lock -ErrorAction Stop | Out-Null
    } catch {
        Write-Host 'ERROR: another frp-client management operation is already running.'
        return $false
    }
    Set-Content -LiteralPath (Join-Path $lock 'pid') -Value ([string]$PID)
    $script:FrpClientLockDepth = 1
    $script:FrpClientLockOwner = $PID
    $script:FrpClientLockPath = $lock
    return $true
}

function Exit-FrpClientLock {
    if ($script:FrpClientLockDepth -gt 1 -and [string]$script:FrpClientLockOwner -eq [string]$PID) {
        $script:FrpClientLockDepth--
        return
    }
    $lock = $script:FrpClientLockPath
    if (-not $lock) { $lock = Get-FrpClientLockPath }
    if ($lock -and (Test-Path -LiteralPath $lock)) {
        Remove-Item -LiteralPath $lock -Recurse -Force -ErrorAction SilentlyContinue
    }
    $script:FrpClientLockDepth = 0
    $script:FrpClientLockOwner = $null
    $script:FrpClientLockPath = $null
}

function Invoke-FrpWithClientLock {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
        return (& $Action)
    } finally {
        Exit-FrpClientLock
    }
}
