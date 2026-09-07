# test-uninstall.ps1
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

$clientPath = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
$hostExe = 'pwsh'
if ($PSVersionTable.PSEdition -eq 'Desktop') { $hostExe = 'powershell.exe' }
try {
    $hp = (Get-Process -Id $PID).Path
    if ($hp) { $hostExe = $hp }
} catch { }

try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    Set-Content -LiteralPath (Get-FrpTomlPath) -Value 'serverAddr = "x"'
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'h' -MachineId $mid -HostId 'h' `
        -Services @(@{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 1; enabled = $true }) `
        -Transport 'tcp' | Out-Null

    $root = Get-FrpWindowsRoot
    Assert-FrpTrue (Test-Path -LiteralPath $root) 'root exists'
    $env:FRP_AUTOSTART_TASK_NAME = 'FRPAutoDeployClient-Test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

    Install-FrpAutostartTask | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists) 'autostart present before uninstall'

    $env:FRP_WINDOWS_FAIL_AUTOSTART = '1'
    $failOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath uninstall 2>&1 | Out-String
    $rcFail = $LASTEXITCODE
    Remove-Item Env:FRP_WINDOWS_FAIL_AUTOSTART -ErrorAction SilentlyContinue
    Assert-FrpEqual 1 $rcFail 'uninstall fails closed when autostart removal fails'
    Assert-FrpTrue ($failOut -match 'leaving product files in place') 'fail-closed uninstall message'
    Assert-FrpTrue (Test-Path -LiteralPath $root) 'product root left in place after failed uninstall'
    Assert-FrpTrue (Test-FrpAutostartTaskExists) 'autostart still present after failed uninstall'

    $okOut = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $clientPath uninstall 2>&1 | Out-String
    $rc = $LASTEXITCODE
    Assert-FrpEqual 0 $rc 'uninstall succeeds after autostart can be removed'
    Assert-FrpTrue ($okOut -match 'SERVER RESERVATIONS PRESERVED') 'uninstall reservation message'
    Assert-FrpTrue (-not (Test-Path -LiteralPath $root)) 'root removed after successful uninstall'
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists)) 'autostart gone after successful uninstall'

    $client = Get-Content -LiteralPath $clientPath -Raw
    Assert-FrpTrue ($client -match 'SERVER RESERVATIONS PRESERVED') 'uninstall message in tool'
    Assert-FrpTrue ($client -match 'leaving product files in place') 'fail-closed uninstall message in tool'

    Write-FrpTestPass 'test-uninstall'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_AUTOSTART -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_AUTOSTART_TASK_NAME -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
