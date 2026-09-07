# test-installed-cli-persistence.ps1 — product CLI works after temp bundle is gone
. (Join-Path $PSScriptRoot 'common.ps1')

$tmpBundle = $null
$installRoot = $null
try {
    $installRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("frp-win-install-" + [guid]::NewGuid().ToString('N'))
    $tmpBundle = Join-Path ([System.IO.Path]::GetTempPath()) ("frp-win-bundle-" + [guid]::NewGuid().ToString('N'))
    $env:FRP_WINDOWS_ROOT = $installRoot

    New-Item -ItemType Directory -Path (Join-Path $tmpBundle 'windows/lib') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tmpBundle 'windows/tools') -Force | Out-Null
    Copy-Item -Path (Join-Path $script:RepoRoot 'windows/lib/*.ps1') -Destination (Join-Path $tmpBundle 'windows/lib') -Force
    Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1') -Destination (Join-Path $tmpBundle 'windows/tools/FrpClient.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'windows/tools/frp-client.cmd') -Destination (Join-Path $tmpBundle 'windows/tools/frp-client.cmd') -Force

    . (Join-Path $tmpBundle 'windows/lib/FrpPaths.ps1')
    . (Join-Path $tmpBundle 'windows/lib/FrpState.ps1')

    # Same permanent install steps as Complete-FrpZeroTouchPostEnroll (tools + lib).
    $script:FrpWindowsSrcRoot = Join-Path $tmpBundle 'windows'
    Initialize-FrpDirectories
    $srcClient = Join-Path $script:FrpWindowsSrcRoot 'tools/FrpClient.ps1'
    $srcCmd = Join-Path $script:FrpWindowsSrcRoot 'tools/frp-client.cmd'
    Copy-Item -LiteralPath $srcClient -Destination (Join-Path (Get-FrpToolsDir) 'FrpClient.ps1') -Force
    Copy-Item -LiteralPath $srcCmd -Destination (Join-Path (Get-FrpToolsDir) 'frp-client.cmd') -Force
    $srcLib = Join-Path $script:FrpWindowsSrcRoot 'lib'
    $destLib = Get-FrpLibDir
    Get-ChildItem -LiteralPath $srcLib -Filter '*.ps1' -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destLib $_.Name) -Force
    }

    Assert-FrpTrue (Test-Path -LiteralPath (Join-Path $destLib 'FrpPaths.ps1')) 'lib FrpPaths installed'
    Assert-FrpTrue (Test-Path -LiteralPath (Join-Path (Get-FrpToolsDir) 'FrpClient.ps1')) 'FrpClient.ps1 installed'

    Remove-Item -LiteralPath $tmpBundle -Recurse -Force
    Assert-FrpTrue (-not (Test-Path -LiteralPath $tmpBundle)) 'temp bundle removed'
    $tmpBundle = $null

    $installedClient = Join-Path $installRoot 'tools/FrpClient.ps1'
    $hostExe = 'pwsh'
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
    try {
        $hp = (Get-Process -Id $PID).Path
        if ($hp) { $hostExe = $hp }
    } catch { }

    $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $installedClient doctor 2>&1 | Out-String
    # Doctor may report missing enroll artifacts (exit 1); modules must still load.
    Assert-FrpTrue ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) ("installed FrpClient doctor runnable; out=$out")
    Assert-FrpTrue ($out -notmatch 'cannot locate windows/lib') 'modules resolved from install root'
    Assert-FrpTrue ($out -match 'frp-client doctor|Doctor|Enrolled') 'doctor ran from installed modules'

    Write-FrpTestPass 'test-installed-cli-persistence'
} finally {
    if ($tmpBundle -and (Test-Path -LiteralPath $tmpBundle)) {
        Remove-Item -LiteralPath $tmpBundle -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($installRoot -and (Test-Path -LiteralPath $installRoot)) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
}
