# test-canonical-cli.ps1 — Windows resource-first drlink grammar + update modes.
. (Join-Path $PSScriptRoot 'common.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-canon-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
$env:FRP_WINDOWS_ROOT = $tmpRoot
try {
    . (Join-Path $script:WindowsLib 'FrpPaths.ps1')
    . (Join-Path $script:WindowsLib 'FrpCrypto.ps1')
    . (Join-Path $script:WindowsLib 'FrpState.ps1')
    Initialize-FrpDirectories
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-cli' -MachineId $mid -HostId 'cliabcd' `
        -Services @{ rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60040; enabled = $true } } `
        -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    $help = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath help 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'help exits 0'
    Assert-FrpTrue ($help -match 'service list') 'help advertises service list'
    Assert-FrpTrue ($help -match 'client info') 'help advertises client info'
    Assert-FrpTrue ($help -match 'update project') 'help advertises update project'
    Assert-FrpTrue ($help -match 'update engine') 'help advertises update engine'
    Assert-FrpTrue ($help -match 're-running the canonical') 'help documents installer project-update path'
    Assert-FrpTrue ($help -match 'support bundle') 'help advertises support bundle'
    Assert-FrpTrue ($help -notmatch 'add-service') 'help hides legacy add-service'

    $list = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath service list 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'service list exits 0'
    Assert-FrpTrue ($list -match 'rdp') 'service list shows rdp'

    $info = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath client info 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'client info exits 0'

    # Resource-first support bundle vocabulary (legacy support-bundle still works).
    $bundleOut = Join-Path $tmpRoot 'bundle-test.zip'
    $bundle = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath support bundle -Output $bundleOut 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'support bundle exits 0'
    Assert-FrpTrue (Test-Path -LiteralPath $bundleOut) 'support bundle wrote archive'

    $add = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath service add `
        -Preset custom -Id web -Name Web -TargetHost 10.0.0.5 -TargetPort 8080 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'service add exits 0'
    Assert-FrpTrue ($add -match 'Pending service web added') 'service add message'

    $check = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath update -Check 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'update --check exits 0'
    Assert-FrpTrue ($check -match 'Data Relay Link project') 'check shows project section'
    Assert-FrpTrue ($check -match 'FRP engine') 'check shows engine section'
    Assert-FrpTrue ($check -match 'Would download:') 'combined check includes engine Would download'
    Assert-FrpTrue ($check -match 're-run the Windows client installer') 'combined check documents installer path'

    # WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS — project -Check is project-only (not engine apply dry-run)
    $projCheck = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath update project -Check 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS exit 0'
    Assert-FrpTrue ($projCheck -match 'Data Relay Link project') 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS shows project'
    Assert-FrpTrue ($projCheck -match 're-run the Windows client installer') 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS installer path'
    Assert-FrpTrue ($projCheck -notmatch 'Would download:') 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS omits engine download'
    Assert-FrpTrue ($projCheck -notmatch 'FRP engine') 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS omits engine section'

    # WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS — engine -Check is engine-only
    $engCheck = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath update engine -Check 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -eq 0) 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS exit 0'
    Assert-FrpTrue ($engCheck -match 'Would download:') 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS Would download'
    Assert-FrpTrue ($engCheck -match 'Expected SHA256:') 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS sha256'
    Assert-FrpTrue ($engCheck -match 'FRP engine') 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS engine header'
    Assert-FrpTrue ($engCheck -notmatch 'Data Relay Link project') 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS omits project section'
    Assert-FrpTrue ($engCheck -notmatch 're-run the Windows client installer') 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS omits installer path'

    # Installed-client project apply is honest: without a distinct source tree, guide to installer.
    $prevSrc = $env:FRP_WINDOWS_PROJECT_SRC
    Remove-Item Env:FRP_WINDOWS_PROJECT_SRC -ErrorAction SilentlyContinue
    try {
        # Point "installed" product root at the temp root so repo windows/ is not used as source.
        # FrpClient still runs from the repo path; Resolve refuses when candidate == product root only.
        # Simulate missing/explicit-denied source by setting FRP_WINDOWS_PROJECT_SRC to the product root.
        $env:FRP_WINDOWS_PROJECT_SRC = $tmpRoot
        $projApply = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath update project 2>&1 | Out-String
        Assert-FrpTrue ($LASTEXITCODE -ne 0) 'update project without source fails'
        Assert-FrpTrue ($projApply -match 'PROJECT_UPDATE_USE_INSTALLER') 'update project FAILURE_CLASS=PROJECT_UPDATE_USE_INSTALLER'
        Assert-FrpTrue ($projApply -match 're-run the canonical Windows client installer') 'update project guides to installer'
    } finally {
        if ($null -ne $prevSrc -and $prevSrc -ne '') {
            $env:FRP_WINDOWS_PROJECT_SRC = $prevSrc
        } else {
            Remove-Item Env:FRP_WINDOWS_PROJECT_SRC -ErrorAction SilentlyContinue
        }
    }

    $bad = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath client nope 2>&1 | Out-String
    Assert-FrpTrue ($LASTEXITCODE -ne 0) 'bad client subcommand fails'

    Write-FrpTestPass 'test-canonical-cli'
    Write-FrpTestPass 'WINDOWS_UPDATE_PROJECT_CHECK_SEMANTICS'
    Write-FrpTestPass 'WINDOWS_UPDATE_ENGINE_CHECK_SEMANTICS'
} finally {
    Remove-Item Env:FRP_WINDOWS_ROOT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
