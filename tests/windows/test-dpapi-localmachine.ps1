# test-dpapi-localmachine.ps1 — production Windows must not fall back to CurrentUser
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $env:FRP_WINDOWS_FAIL_DPAPI_LOCALMACHINE = '1'
    $threw = $false
    try {
        Assert-FrpLocalMachineDpapiAvailable
    } catch {
        $threw = $true
        $msg = [string]$_
        Assert-FrpTrue ($msg -match 'LocalMachine DPAPI') ("identity key fail-closed message: $msg")
    }
    Assert-FrpTrue $threw 'LocalMachine DPAPI helper fails closed'
    Remove-Item Env:FRP_WINDOWS_FAIL_DPAPI_LOCALMACHINE -ErrorAction SilentlyContinue

    $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'windows\lib\FrpState.ps1') -Raw
    Assert-FrpTrue ($src -notmatch 'DataProtectionScope\]::CurrentUser') 'no CurrentUser DPAPI fallback in FrpState.ps1'
    Assert-FrpTrue ($src -match 'Assert-FrpLocalMachineDpapiAvailable') 'Save/Read paths require LocalMachine helper'

    Write-FrpTestPass 'test-dpapi-localmachine'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_DPAPI_LOCALMACHINE -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
