# test-autostart.ps1 — product autostart task lifecycle (non-Windows marker
# backend) + zero-touch wiring + uninstall cleanup + FrpClient.ps1 CLI.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    # Isolate from any leftover product/E2E scheduled task on Windows CI hosts.
    $env:FRP_AUTOSTART_TASK_NAME = 'FRPAutoDeployClient-Test-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $taskName = Get-FrpAutostartTaskName
    Assert-FrpEqual $env:FRP_AUTOSTART_TASK_NAME $taskName 'product-owned task name'
    # Never collides with the E2E reverse-SSH scheduled task.
    Assert-FrpTrue ($taskName -notmatch '(?i)reverse|ssh|e2e') 'task name does not look like the E2E reverse-SSH task'
    try { Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null } catch { }

    # --- Low-level register/query/remove (marker backend on non-Windows) -----
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists -TaskName $taskName)) 'not registered initially'
    Install-FrpAutostartTask | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists) 'registered after install'
    $runCmd = Get-FrpAutostartRunCommand
    $runArgs = Get-FrpAutostartRunArguments
    Assert-FrpTrue ($runCmd -match 'frp-autostart\.cmd$') 'run command targets frp-autostart.cmd'
    Assert-FrpEqual '' $runArgs 'run arguments empty (wrapper owns start)'
    Assert-FrpTrue ($runCmd -match [regex]::Escape((Get-FrpToolsDir))) 'run command uses the persisted tools dir, not the temp bootstrap tree'
    $xml = New-FrpAutostartTaskXml -Command $runCmd -Arguments $runArgs
    Assert-FrpTrue ($xml -match 'DisallowStartIfOnBatteries>false') 'battery disallow disabled'
    Assert-FrpTrue ($xml -match 'S-1-5-18') 'runs as SYSTEM'
    Assert-FrpTrue ($xml -match 'BootTrigger') 'boot trigger present'

    # Idempotent: re-install (overwrite) does not throw.
    Install-FrpAutostartTask | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists) 'still registered after re-install'

    Uninstall-FrpAutostartTask | Out-Null
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists)) 'removed after uninstall'
    # Idempotent: uninstalling an already-absent task is success, not an error.
    Uninstall-FrpAutostartTask | Out-Null

    # Simulated failure hook (mirrors FRP_WINDOWS_FAIL_ACL pattern).
    $env:FRP_WINDOWS_FAIL_AUTOSTART = '1'
    $threw = $false
    try { Install-FrpAutostartTask | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'install honors FRP_WINDOWS_FAIL_AUTOSTART'
    $threw = $false
    try { Uninstall-FrpAutostartTask | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'uninstall honors FRP_WINDOWS_FAIL_AUTOSTART'
    Remove-Item Env:FRP_WINDOWS_FAIL_AUTOSTART -ErrorAction SilentlyContinue
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists)) 'still not registered after failed install attempt'

    Write-FrpTestPass 'test-autostart (register/query/remove)'

    # --- Zero-touch wiring: registers only when frpc actually needs to run ---
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60050; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null

    Complete-FrpZeroTouchPostEnroll -SkipDownload -SkipStart -Services $services | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists) 'autostart registered for a client with enabled services'
    Uninstall-FrpAutostartTask | Out-Null

    Write-FrpTestPass 'test-autostart (zero-touch registers for services)'

    # Management-only: no frpc to run, autostart must not be registered.
    Remove-FrpDraftState | Out-Null
    $mid2 = 'deadbeefcafedeadbeefcafedeadbef'
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win2' -MachineId $mid2 -HostId 'wxyz' `
        -Services @{} -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'wxyz' -Services @{} -Transport 'tcp' | Out-Null
    Complete-FrpZeroTouchPostEnroll -SkipDownload -SkipStart -Services @{} | Out-Null
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists)) 'management-only client does not register autostart'

    Write-FrpTestPass 'test-autostart (management-only skips registration)'

    # Registration failure must not abort enrollment (non-fatal warning).
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'enrolled_incomplete' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
        -HostId 'abcd' -Services $services -Transport 'tcp' | Out-Null
    $env:FRP_WINDOWS_FAIL_AUTOSTART = '1'
    $rc = Complete-FrpZeroTouchPostEnroll -SkipDownload -SkipStart -Services $services
    Remove-Item Env:FRP_WINDOWS_FAIL_AUTOSTART -ErrorAction SilentlyContinue
    Assert-FrpEqual 0 $rc 'enrollment still succeeds when autostart registration fails'
    Assert-FrpEqual 'installed' (Get-FrpInstallStatus) 'install completes despite autostart failure'

    Write-FrpTestPass 'test-autostart (registration failure is non-fatal)'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_AUTOSTART -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
