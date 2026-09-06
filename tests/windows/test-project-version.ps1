# test-project-version.ps1 — Windows fallback matches canonical VERSION
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $expected = $null
    foreach ($line in Get-Content -LiteralPath (Join-Path $script:RepoRoot 'VERSION')) {
        if ($line -match '^\s*PROJECT_VERSION\s*=\s*(.+)\s*$') {
            $expected = $Matches[1].Trim()
            break
        }
    }
    Assert-FrpTrue (-not [string]::IsNullOrWhiteSpace($expected)) 'VERSION PROJECT_VERSION present'

    Remove-Item Env:PROJECT_VERSION -ErrorAction SilentlyContinue
    $got = Get-FrpProjectVersion
    Assert-FrpEqual $expected $got 'Get-FrpProjectVersion matches VERSION'
    Assert-FrpTrue ($got -ne '2.1.1') 'stale 2.1.1 fallback removed'

    Write-FrpTestPass 'test-project-version'
} finally {
    Remove-FrpWindowsTestRoot
}
