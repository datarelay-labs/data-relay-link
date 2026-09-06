# test-pid-ownership.ps1 — PID metadata + refuse kill on mismatched process
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    if (Test-FrpIsWindowsHost) {
        Write-Host 'SKIP test-pid-ownership on Windows host (uses fake sleep on Linux CI)'
        exit 0
    }
    $env:FRP_WINDOWS_ALLOW_FAKE_PROCESS = '1'
    New-Item -ItemType Directory -Path (Get-FrpConfigDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpTomlPath) -Value "serverAddr = `"127.0.0.1`"`n"
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'dummy'

    $managedPid = Start-FrpClient
    $meta = Read-FrpPidMetadata
    Assert-FrpTrue ($null -ne $meta) 'metadata present'
    Assert-FrpEqual ([int]$managedPid) ([int]$meta.pid) 'pid matches'
    Assert-FrpTrue (-not [string]::IsNullOrWhiteSpace([string]$meta.exe)) 'exe recorded'
    Assert-FrpTrue (Test-FrpProcessAlive -ProcessId $managedPid -ValidateOwnership -ExpectedExe $meta.exe) 'owned alive'
    Stop-FrpClient | Out-Null

    # Point metadata at unrelated live process with frpc expected exe => ownership fail => no kill
    $unrelated = $PID
    Write-FrpPidFile -ProcessId $unrelated -ExePath (Get-FrpFrpcPath)
    Assert-FrpTrue (-not (Test-FrpProcessOwned -ProcessId $unrelated -ExpectedExe (Get-FrpFrpcPath))) 'pwsh not owned frpc'
    $stopped = Stop-FrpClient
    Assert-FrpTrue (-not $stopped) 'did not kill unrelated'
    Assert-FrpTrue ($null -ne (Get-Process -Id $unrelated -ErrorAction SilentlyContinue)) 'unrelated still alive'
    Assert-FrpTrue ($null -eq (Read-FrpPidMetadata)) 'metadata cleared'

    # Same basename, different absolute path => not owned when Path is available.
    # Simulate via a live process whose Path leaf is not frpc but we force expected
    # to a path with the same leaf as a fake sibling binary.
    $fakeOther = Join-Path (Get-FrpBinDir) 'other-frpc.exe'
    Set-Content -LiteralPath $fakeOther -Value 'dummy-other'
    $selfPath = $null
    try { $selfPath = (Get-Process -Id $PID).Path } catch { $selfPath = $null }
    if ($selfPath) {
        # Current host process Path is available and does not match ExpectedExe.
        Assert-FrpTrue (-not (Test-FrpProcessOwned -ProcessId $PID -ExpectedExe $fakeOther)) 'different absolute path not owned'
    }

    Write-FrpTestPass 'test-pid-ownership'
} finally {
    Remove-Item Env:FRP_WINDOWS_ALLOW_FAKE_PROCESS -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
