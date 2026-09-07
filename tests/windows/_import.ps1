# Dot-source this file (not call as a function) so module functions enter the caller scope.
$ErrorActionPreference = 'Stop'

if (-not $script:WindowsLib) {
    . (Join-Path $PSScriptRoot 'common.ps1')
}

$env:FRP_WINDOWS_ROOT = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $env:FRP_WINDOWS_ROOT -Force | Out-Null
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null } catch { }

foreach ($mod in @(
        'FrpPaths.ps1', 'FrpLock.ps1', 'FrpCrypto.ps1', 'FrpTls.ps1', 'FrpState.ps1', 'FrpDraft.ps1',
        'FrpConfig.ps1', 'FrpProcess.ps1', 'FrpAutostart.ps1', 'FrpBootstrap.ps1'
    )) {
    . (Join-Path $script:WindowsLib $mod)
}
Initialize-FrpCryptoTypes
Initialize-FrpDirectories
