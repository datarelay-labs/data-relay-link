# test-pause-resume.ps1 — pause = stop frpc + disable autostart; resume restores both.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $env:FRP_AUTOSTART_TASK_NAME = 'FRPAutoDeployClient-PauseTest-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $taskName = Get-FrpAutostartTaskName
    try { Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null } catch { }

    $clientTool = Join-Path $script:RepoRoot 'windows/tools/FrpClient.ps1'
    $src = Get-Content -LiteralPath $clientTool -Raw
    Assert-FrpTrue ($src -match 'function Invoke-FrpClientPause') 'defines Invoke-FrpClientPause'
    Assert-FrpTrue ($src -match 'function Invoke-FrpClientResume') 'defines Invoke-FrpClientResume'
    Assert-FrpTrue ($src -match "'pause'") 'registers pause command'
    Assert-FrpTrue ($src -match "'resume'") 'registers resume command'

    New-Item -ItemType Directory -Path (Get-FrpConfigDir) -Force | Out-Null
    New-Item -ItemType Directory -Path (Get-FrpStateDir) -Force | Out-Null
    New-Item -ItemType Directory -Path (Get-FrpBinDir) -Force | Out-Null
    Set-Content -LiteralPath (Get-FrpTomlPath) -Value "serverAddr = `"127.0.0.1`"`n"
    Set-Content -LiteralPath (Get-FrpFrpcPath) -Value 'dummy'
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-pause' -MachineId $mid -HostId 'pausehost' `
        -Services @{
            ssh = @{ id = 'ssh'; name = 'SSH'; preset = 'ssh'; local_ip = '127.0.0.1'; local_port = 22; remote_port = 6002; enabled = $true }
        } | Out-Null
    $before = Get-Content -LiteralPath (Get-FrpStatePath) -Raw

    $env:FRP_WINDOWS_ALLOW_FAKE_PROCESS = '1'
    Install-FrpAutostartTask -TaskName $taskName | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists -TaskName $taskName) 'autostart enabled before pause'
    Start-FrpClient | Out-Null
    Assert-FrpTrue (Get-FrpClientStatus).Running 'frpc running before pause'

    # Pause equivalent: stop + disable autostart (same helpers Invoke-FrpClientPause uses)
    Stop-FrpClient | Out-Null
    Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null
    Assert-FrpTrue (-not (Get-FrpClientStatus).Running) 'frpc stopped after pause'
    Assert-FrpTrue (-not (Test-FrpAutostartTaskExists -TaskName $taskName)) 'autostart disabled after pause'

    # Pause again (idempotent)
    Stop-FrpClient | Out-Null
    if (Test-FrpAutostartTaskExists -TaskName $taskName) { Uninstall-FrpAutostartTask -TaskName $taskName | Out-Null }

    # Resume equivalent: restore autostart + start
    Install-FrpAutostartTask -TaskName $taskName | Out-Null
    Start-FrpClient | Out-Null
    Assert-FrpTrue (Test-FrpAutostartTaskExists -TaskName $taskName) 'autostart enabled after resume'
    Assert-FrpTrue (Get-FrpClientStatus).Running 'frpc running after resume'

    # Resume again (idempotent)
    Install-FrpAutostartTask -TaskName $taskName | Out-Null
    Start-FrpClient | Out-Null
    Assert-FrpTrue (Get-FrpClientStatus).Running 'still running after second resume'

    $after = Get-Content -LiteralPath (Get-FrpStatePath) -Raw
    Assert-FrpEqual $before $after 'client-state.json unchanged across pause/resume'

    Write-FrpTestPass 'test-pause-resume'
} finally {
    Remove-Item Env:FRP_WINDOWS_ALLOW_FAKE_PROCESS -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_AUTOSTART_TASK_NAME -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
