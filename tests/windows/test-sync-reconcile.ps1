# test-sync-reconcile.ps1 — Windows reconcile/sync/apply fail-closed + local-only apply
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $macKey = New-FrpNonce
    Save-FrpIdentityMac -MacKeyHex $macKey | Out-Null

    function New-FrpTestServices {
        return @{
            ssh = @{ id = 'ssh'; name = 'SSH'; preset = 'ssh'; local_ip = '127.0.0.1'; local_port = 22; remote_port = 6002; enabled = $true; ssh_user = 'aella' }
            web = @{ id = 'web'; name = 'Web'; preset = 'custom'; local_ip = '127.0.0.1'; local_port = 18080; remote_port = 6003; enabled = $true }
        }
    }

    function Reset-FrpFixture {
        $svc = New-FrpTestServices
        Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
            -FrpServerPort 7000 -Hostname 'win' -MachineId $mid -HostId 'h' `
            -Services $svc -Transport 'tcp' -InstallStatus 'installed' | Out-Null
        New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok' `
            -HostId 'h' -Services $svc -Transport 'tcp' | Out-Null
    }

    Reset-FrpFixture
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $ok = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue ([bool]$ok) 'successful reconcile'
    $map = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue ($map.Contains('ssh')) 'ssh kept'
    Assert-FrpTrue (-not $map.Contains('web')) 'web dropped'

    Reset-FrpFixture
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh","web"]'
    $noop = Invoke-FrpReconcileReleasedServices
    Assert-FrpTrue (-not $noop) 'no-op reconcile'

    Reset-FrpFixture
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue
    $env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE = '1'
    $threw = $false
    try { $null = Invoke-FrpReconcileReleasedServices } catch { $threw = $true }
    Assert-FrpTrue $threw 'unreachable throws'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -ErrorAction SilentlyContinue

    $env:FRP_CLIENT_HOOK_RECONCILE_HMAC = '1'
    $threw = $false
    try { $null = Invoke-FrpReconcileReleasedServices } catch { $threw = $true }
    Assert-FrpTrue $threw 'hmac throws'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_HMAC -ErrorAction SilentlyContinue

    $env:FRP_CLIENT_HOOK_RECONCILE_MALFORMED = '1'
    $threw = $false
    try { $null = Invoke-FrpReconcileReleasedServices } catch { $threw = $true }
    Assert-FrpTrue $threw 'malformed throws'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_MALFORMED -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $env:FRP_CLIENT_HOOK_TOML_REGEN = '1'
    $threw = $false
    try { $null = Invoke-FrpReconcileReleasedServices } catch { $threw = $true }
    Assert-FrpTrue $threw 'toml regen failure throws'
    $map = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue (-not $map.Contains('web')) 'toml failure does not restore released service'
    Remove-Item Env:FRP_CLIENT_HOOK_TOML_REGEN -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $env:FRP_CLIENT_HOOK_RESTART_FAIL = '1'
    $threw = $false
    try { $null = Invoke-FrpReconcileReleasedServices } catch { $threw = $true }
    Assert-FrpTrue $threw 'restart failure throws'
    Remove-Item Env:FRP_CLIENT_HOOK_RESTART_FAIL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $script:HostLog = New-Object System.Collections.ArrayList
    function Write-Host {
        param([Parameter(Position = 0, ValueFromRemainingArguments = $true)]$Object)
        [void]$script:HostLog.Add([string]$Object)
        Microsoft.PowerShell.Utility\Write-Host -Object $Object
    }
    $env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE = '1'
    $rc = Invoke-FrpClientSync
    Assert-FrpEqual 1 $rc 'explicit sync returns non-zero on failure'
    $log = ($script:HostLog -join "`n")
    Assert-FrpTrue ($log -notmatch 'Client sync complete\.') 'sync does not print success on failure'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $script:HostLog = New-Object System.Collections.ArrayList
    $env:FRP_SKIP_CONNECTIVITY_CHECK = '1'
    $rcOk = Invoke-FrpClientSync
    Assert-FrpEqual 0 $rcOk 'sync no-op under skip is success'
    $logOk = ($script:HostLog -join "`n")
    Assert-FrpTrue ($logOk -match 'Client sync complete\.') 'sync success line on no-op'

    Reset-FrpFixture
    $null = Remove-FrpDraftState
    Add-FrpDraftService -Preset 'custom' -Id 'extra' -Name 'Extra' -TargetHost '10.0.0.5' -TargetPort 8080 | Out-Null
    $env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE = '1'
    Remove-Item Env:FRP_SKIP_CONNECTIVITY_CHECK -ErrorAction SilentlyContinue
    $script:HostLog = New-Object System.Collections.ArrayList
    $pre = Get-Content -LiteralPath (Get-FrpStatePath) -Raw
    $rcApply = Invoke-FrpClientApplyDraft
    Assert-FrpEqual 1 $rcApply 'apply aborts after required reconcile failure'
    $applyLog = ($script:HostLog -join "`n")
    Assert-FrpTrue ($applyLog -match 'cannot apply because client synchronization failed') 'apply reports reconcile failure'
    Assert-FrpEqual $pre (Get-Content -LiteralPath (Get-FrpStatePath) -Raw) 'apply did not mutate state'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $null = Remove-FrpDraftState
    Ensure-FrpDraftPending | Out-Null
    Set-FrpDraftServiceField -Id 'ssh' -Property 'name' -Value 'Office SSH' | Out-Null
    $env:FRP_SKIP_CONNECTIVITY_CHECK = '1'
    $env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE = '1'
    $script:HostLog = New-Object System.Collections.ArrayList
    $httpsCalls = 0
    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        $script:httpsCalls++
        throw 'ERROR: allocator should not be contacted for local-only apply'
    }
    $rcLocal = Invoke-FrpClientApplyDraft
    Assert-FrpEqual 0 $rcLocal 'local-only apply succeeds'
    $localLog = ($script:HostLog -join "`n")
    Assert-FrpTrue ($localLog -match 'Allocator contacted : NO') 'local-only allocator line'
    Assert-FrpTrue ($localLog -match 'frpc restarted      : NO') 'local-only restart line'
    Assert-FrpEqual 0 $httpsCalls 'local-only did not HTTP'
    $afterMap = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpEqual 'Office SSH' ([string]$afterMap['ssh'].name) 'local name applied'
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_SKIP_CONNECTIVITY_CHECK -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $null = Remove-FrpDraftState
    Add-FrpDraftService -Preset 'custom' -Id 'e2ehttp' -Name 'e2ehttp' -TargetHost '127.0.0.1' -TargetPort 18080 | Out-Null
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh","web"]'
    $null = Invoke-FrpReconcileReleasedServices
    $committed = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue ($committed.Contains('ssh')) 'pending-add committed keeps ssh'
    Assert-FrpTrue ($committed.Contains('web')) 'pending-add committed keeps web'
    Assert-FrpTrue (-not $committed.Contains('e2ehttp')) 'pending-add not committed yet'
    $draftKept = ConvertTo-FrpServiceMap -Services (Read-FrpDraftState).services
    Assert-FrpTrue ($draftKept.Contains('e2ehttp')) 'pending add survives reconcile'
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue

    Reset-FrpFixture
    $null = Remove-FrpDraftState
    Add-FrpDraftService -Preset 'custom' -Id 'e2ehttp' -Name 'e2ehttp' -TargetHost '127.0.0.1' -TargetPort 18080 | Out-Null
    $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS = '["ssh"]'
    $null = Invoke-FrpReconcileReleasedServices
    $committed2 = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpTrue ($committed2.Contains('ssh')) 'released+pending keeps ssh'
    Assert-FrpTrue (-not $committed2.Contains('web')) 'released web dropped from committed'
    $draftMixed = ConvertTo-FrpServiceMap -Services (Read-FrpDraftState).services
    Assert-FrpTrue ($draftMixed.Contains('ssh')) 'draft keeps ssh'
    Assert-FrpTrue (-not $draftMixed.Contains('web')) 'draft drops released web'
    Assert-FrpTrue ($draftMixed.Contains('e2ehttp')) 'draft keeps pending add after release prune'
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue

    Write-FrpTestPass 'test-sync-reconcile'
} finally {
    Remove-Item Env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_HMAC -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_HOOK_RECONCILE_MALFORMED -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_HOOK_TOML_REGEN -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_CLIENT_HOOK_RESTART_FAIL -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_SKIP_CONNECTIVITY_CHECK -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
