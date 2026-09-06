# test-draft-crud.ps1 — client-draft.json CRUD (add/set/enable/disable/discard)
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $mid = Get-FrpOrCreateClientId
    $services = @{
        rdp = @{
            id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'
            local_port = 3389; remote_port = 60010; enabled = $true
        }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'abcd' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null

    # No draft yet.
    Assert-FrpTrue (-not (Test-FrpDraftPending)) 'no draft initially'

    # add-service creates the draft from current state and adds the new entry.
    $sid = Add-FrpDraftService -Preset 'custom' -Id 'web' -Name 'Web' -TargetHost '10.0.0.5' -TargetPort 8080
    Assert-FrpEqual 'web' $sid 'returned id'
    Assert-FrpTrue (Test-FrpDraftPending) 'draft created'
    $map = Get-FrpDraftServiceMap
    Assert-FrpEqual 2 $map.Count 'two pending services'
    Assert-FrpEqual '10.0.0.5' $map['web'].local_ip 'web target host'
    Assert-FrpEqual 8080 ([int]$map['web'].local_port) 'web target port'
    Assert-FrpTrue ([bool]$map['web'].enabled) 'web enabled by default'
    # Original service carried over from client-state.json into the draft.
    Assert-FrpEqual 60010 ([int]$map['rdp'].remote_port) 'rdp remote_port carried into draft'

    # Duplicate id rejected.
    $threw = $false
    try { Add-FrpDraftService -Preset 'custom' -Id 'web' -TargetPort 9090 | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'duplicate service id rejected'

    # Invalid id rejected.
    $threw = $false
    try { Add-FrpDraftService -Preset 'custom' -Id 'Bad Id!' -TargetPort 81 | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'invalid service id rejected'

    # ssh preset requires -SshUser.
    $threw = $false
    try { Add-FrpDraftService -Preset 'ssh' | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'ssh without ssh_user rejected'
    Add-FrpDraftService -Preset 'ssh' -SshUser 'alice' | Out-Null
    $map = Get-FrpDraftServiceMap
    Assert-FrpEqual 'alice' $map['ssh'].ssh_user 'ssh_user stored'
    Assert-FrpEqual 22 ([int]$map['ssh'].local_port) 'ssh default port'

    # set-service edits target without touching remote_port (public port preserved).
    Set-FrpDraftServiceField -Id 'rdp' -Property 'target-host' -Value '10.0.0.9' | Out-Null
    Set-FrpDraftServiceField -Id 'rdp' -Property 'target-port' -Value '3390' | Out-Null
    $map = Get-FrpDraftServiceMap
    Assert-FrpEqual '10.0.0.9' $map['rdp'].local_ip 'rdp target host updated'
    Assert-FrpEqual 3390 ([int]$map['rdp'].local_port) 'rdp target port updated'
    Assert-FrpEqual 60010 ([int]$map['rdp'].remote_port) 'rdp remote_port preserved after edit'

    # set-service on unknown id fails.
    $threw = $false
    try { Set-FrpDraftServiceField -Id 'nope' -Property 'name' -Value 'x' | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'unknown service id rejected'

    # ssh-user only valid for ssh preset.
    $threw = $false
    try { Set-FrpDraftServiceField -Id 'web' -Property 'ssh-user' -Value 'bob' | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'ssh-user rejected for non-ssh service'

    # disable preserves remote_port (public reservation).
    $nowEnabled = Set-FrpDraftServiceEnabled -Id 'web' -Enable $false
    Assert-FrpTrue (-not $nowEnabled) 'web disabled'
    $map = Get-FrpDraftServiceMap
    Assert-FrpTrue (-not [bool]$map['web'].enabled) 'web disabled in map'

    # enable reuses the same (still unset for a never-applied service, but present) shape;
    # re-enable does not error and flips the flag back.
    $nowEnabled = Set-FrpDraftServiceEnabled -Id 'web' -Enable $true
    Assert-FrpTrue $nowEnabled 'web re-enabled'

    # Disabling the last enabled service is rejected.
    Set-FrpDraftServiceEnabled -Id 'web' -Enable $false | Out-Null
    Set-FrpDraftServiceEnabled -Id 'ssh' -Enable $false | Out-Null
    $threw = $false
    try { Set-FrpDraftServiceEnabled -Id 'rdp' -Enable $false | Out-Null } catch { $threw = $true }
    Assert-FrpTrue $threw 'cannot disable last enabled service'

    # discard removes the draft entirely; client-state.json is untouched.
    $existed = Remove-FrpDraftState
    Assert-FrpTrue $existed 'draft existed before discard'
    Assert-FrpTrue (-not (Test-FrpDraftPending)) 'draft removed'
    $state = Read-FrpClientState
    $stateMap = ConvertTo-FrpServiceMap -Services $state.services
    Assert-FrpEqual 1 $stateMap.Count 'client-state.json unaffected by discarded draft'

    # discard with nothing pending reports no-op, not an error.
    $existed2 = Remove-FrpDraftState
    Assert-FrpTrue (-not $existed2) 'second discard is a no-op'

    Write-FrpTestPass 'test-draft-crud'
} finally {
    Remove-FrpWindowsTestRoot
}
