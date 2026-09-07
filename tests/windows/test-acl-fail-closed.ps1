# test-acl-fail-closed.ps1 — Restrict-FrpFileAcl fail-closed + fixed-time compare
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $path = Join-Path (Get-FrpStateDir) 'secret-test.txt'
    Set-Content -LiteralPath $path -Value 'secret'

    $env:FRP_WINDOWS_FAIL_ACL = '1'
    $threw = $false
    try {
        Restrict-FrpFileAcl -Path $path
    } catch {
        $threw = $true
        Assert-FrpTrue ($_.Exception.Message -match 'ACL') 'ACL mentioned'
    }
    Assert-FrpTrue $threw 'ACL failure throws (fail closed)'
    Remove-Item Env:FRP_WINDOWS_FAIL_ACL -ErrorAction SilentlyContinue

    Restrict-FrpFileAcl -Path $path

    Assert-FrpTrue (Test-FrpFixedTimeEquals -Left 'abc' -Right 'abc') 'equal ok'
    Assert-FrpTrue (-not (Test-FrpFixedTimeEquals -Left 'abc' -Right 'abd')) 'diff rejected'
    Assert-FrpTrue (-not (Test-FrpFixedTimeEquals -Left 'abc' -Right 'ab')) 'length mismatch'
    Assert-FrpTrue (Test-FrpFixedTimeEquals -Left 'AbC' -Right 'abc' -IgnoreCase) 'ignore case'

    Write-FrpTestPass 'test-acl-fail-closed'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_ACL -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
