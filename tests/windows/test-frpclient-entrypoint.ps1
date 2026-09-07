# test-frpclient-entrypoint.ps1 — powershell -File FrpClient.ps1 must expose lib functions
. (Join-Path $PSScriptRoot 'common.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$src = Get-Content -LiteralPath $clientPath -Raw
Assert-FrpTrue ($src -match '(?m)^\s*\. Import-FrpWindowsModules\s*$') 'dot-sources Import-FrpWindowsModules into script scope'

$hosts = New-Object System.Collections.ArrayList
[void]$hosts.Add((Get-Process -Id $PID).Path)
if ($env:SystemRoot) {
    $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $winPs) {
        [void]$hosts.Add($winPs)
    }
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-entry-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
$env:FRP_WINDOWS_ROOT = $tmpRoot
try {
    foreach ($exe in @($hosts | Select-Object -Unique)) {
        $label = Split-Path -Leaf $exe
        $doctorOut = & $exe -NoProfile -ExecutionPolicy Bypass -File $clientPath -Command doctor 2>&1 | Out-String
        Assert-FrpTrue ($doctorOut -match 'frp-client doctor') "$label doctor entrypoint ran"
        Assert-FrpTrue ($doctorOut -match 'Root:') "$label doctor called Get-FrpWindowsRoot"
        Assert-FrpTrue ($doctorOut -notmatch 'is not recognized') "$label doctor has module functions"

        $statusOut = & $exe -NoProfile -ExecutionPolicy Bypass -File $clientPath -Command status 2>&1 | Out-String
        Assert-FrpTrue ($statusOut -match 'enrolled=') "$label status entrypoint ran"
        Assert-FrpTrue ($statusOut -notmatch 'is not recognized') "$label status has module functions"

        $checkOut = & $exe -NoProfile -ExecutionPolicy Bypass -File $clientPath -Command update -Check 2>&1 | Out-String
        Assert-FrpTrue ($checkOut -match 'Would download:') "$label update -Check binds to script switch"
        Assert-FrpTrue ($checkOut -match 'preserved') "$label update -Check is dry-run"
        Assert-FrpTrue ($checkOut -notmatch 'is not recognized') "$label update -Check has Get-FrpWindowsAmd64Url"
    }
    Write-FrpTestPass 'test-frpclient-entrypoint'
} finally {
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
