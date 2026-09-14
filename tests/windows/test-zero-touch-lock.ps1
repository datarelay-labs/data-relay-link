# test-zero-touch-lock.ps1 — F20: Zero-Touch mutable transaction is serialized
# by the product client lifecycle lock. Two simultaneous installers on the same
# root must not split identity or interleave pending/enrollment state.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

$worker = Join-Path $PSScriptRoot 'helpers/zero-touch-worker.ps1'
Assert-FrpTrue (Test-Path -LiteralPath $worker) 'zero-touch worker helper present'

$root = $env:FRP_WINDOWS_ROOT
$caBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($caBytes)
$caSha = ([BitConverter]::ToString($caBytes) -replace '-', '').ToLowerInvariant()
$r1 = Join-Path $root 'zt-lock-a.json'
$r2 = Join-Path $root 'zt-lock-b.json'

function Wait-FrpWorker {
    param($Process, [int]$TimeoutSec = 90)
    if (-not $Process) { return }
    if ($Process.HasExited) { return }
    try {
        Wait-Process -Id $Process.Id -Timeout $TimeoutSec -ErrorAction SilentlyContinue
    } catch { }
    if (-not $Process.HasExited) {
        try { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue } catch { }
    }
}

try {
    $startArgs = @{
        FilePath = $hostExe
        ArgumentList = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $worker,
            '-Root', $root, '-CaSha256', $caSha, '-ResultPath', $r1, '-RedeemDelaySeconds', '4'
        )
        PassThru = $true
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $startArgs['WindowStyle'] = 'Hidden' }
    $p1 = Start-Process @startArgs
    Start-Sleep -Milliseconds 600
    $startArgs2 = @{
        FilePath = $hostExe
        ArgumentList = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $worker,
            '-Root', $root, '-CaSha256', $caSha, '-ResultPath', $r2, '-RedeemDelaySeconds', '0'
        )
        PassThru = $true
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $startArgs2['WindowStyle'] = 'Hidden' }
    $p2 = Start-Process @startArgs2

    Wait-FrpWorker $p1
    Wait-FrpWorker $p2

    Assert-FrpTrue (Test-Path -LiteralPath $r1) 'worker A wrote result'
    Assert-FrpTrue (Test-Path -LiteralPath $r2) 'worker B wrote result'
    $a = Get-Content -LiteralPath $r1 -Raw | ConvertFrom-Json
    $b = Get-Content -LiteralPath $r2 -Raw | ConvertFrom-Json

    $successCount = @(@($a, $b) | Where-Object { [int]$_.rc -eq 0 }).Count
    $failCount = @(@($a, $b) | Where-Object { [int]$_.rc -ne 0 }).Count
    Assert-FrpEqual 1 $successCount ("exactly one Zero-Touch transaction succeeds (a=$($a.rc) b=$($b.rc) ae=$($a.error) be=$($b.error))")
    Assert-FrpTrue ($failCount -ge 1) ("peer is refused by lifecycle lock (a=$($a.rc) b=$($b.rc))")

    $idPath = Get-FrpClientIdPath
    if (Test-Path -LiteralPath $idPath) {
        $mid = ([string](Get-Content -LiteralPath $idPath -Raw)).Trim()
        Assert-FrpTrue ($mid.Length -ge 16) 'surviving client-id is well-formed'
    }
    $pending = @(Get-ChildItem -LiteralPath (Get-FrpStateDir) -Filter 'pending-enroll*.json' -ErrorAction SilentlyContinue)
    Assert-FrpTrue ($pending.Count -le 1) 'no interleaved pending-enroll records'

    Write-FrpTestPass 'test-zero-touch-lock'
} finally {
    foreach ($p in @($p1, $p2)) {
        if ($p -and -not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch { } }
    }
    Remove-FrpWindowsTestRoot
}
