# test-apply-transaction.ps1 — Windows apply local/server compensation
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

function New-FrpSignedEnrollResponse {
    param($Services)
    $respObj = [ordered]@{
        frp_server      = 'example.test'
        frp_server_port = 7000
        frp_transport   = 'tcp'
        services        = @($Services)
    }
    $canonicalNoHmac = Get-FrpCanonicalJson -Object $respObj
    $mac = Read-FrpIdentityMac
    $respObj['response_hmac'] = (Get-FrpHmacHex -Secret $mac -Message $canonicalNoHmac)
    return (Get-FrpCanonicalJson -Object $respObj)
}

try {
    $id = New-FrpEcdsaIdentity
    Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
    Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
    $mid = Get-FrpOrCreateClientId
    $macKey = New-FrpNonce
    Save-FrpIdentityMac -MacKeyHex $macKey | Out-Null

    $services = @{
        rdp = @{ id = 'rdp'; name = 'RDP'; preset = 'rdp'; local_ip = '127.0.0.1'; local_port = 3389; remote_port = 60030; enabled = $true }
    }
    Save-FrpClientState -AllocatorUrl 'https://example.test/enroll' -FrpServer 'example.test' `
        -FrpServerPort 7000 -Hostname 'win-test' -MachineId $mid -HostId 'abcd1234' `
        -Services $services -Transport 'tcp' -InstallStatus 'installed' | Out-Null
    New-FrpClientToml -ServerAddr 'example.test' -ServerPort 7000 -Token 'tok-existing' `
        -HostId 'abcd1234' -Services $services -Transport 'tcp' | Out-Null
    Add-FrpDraftService -Preset 'custom' -Id 'web' -Name 'Web' -TargetHost '10.0.0.5' -TargetPort 8080 | Out-Null

    $preToml = Get-Content -LiteralPath (Get-FrpTomlPath) -Raw
    $preState = Get-Content -LiteralPath (Get-FrpStatePath) -Raw
    $env:FRP_SKIP_CONNECTIVITY_CHECK = '1'
    $script:EnrollCalls = 0
    $script:EnrollBodies = New-Object System.Collections.ArrayList
    $script:HostLog = New-Object System.Collections.ArrayList
    function Write-Host {
        param([Parameter(Position = 0, ValueFromRemainingArguments = $true)]$Object)
        [void]$script:HostLog.Add([string]$Object)
        Microsoft.PowerShell.Utility\Write-Host -Object $Object
    }

    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        $script:EnrollCalls++
        [void]$script:EnrollBodies.Add($Body)
        if ($script:EnrollCalls -eq 1) {
            return (New-FrpSignedEnrollResponse -Services @(
                    [ordered]@{ id = 'rdp'; remote_port = 60030 }
                    [ordered]@{ id = 'web'; remote_port = 60031 }
                ))
        }
        return (New-FrpSignedEnrollResponse -Services @(
                [ordered]@{ id = 'rdp'; remote_port = 60030 }
            ))
    }

    $env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE = '1'
    $rc = Invoke-FrpClientApplyDraft
    Remove-Item Env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -ErrorAction SilentlyContinue
    $log = ($script:HostLog -join "`n")
    Assert-FrpEqual 1 $rc 'apply fails after allocator commit when local activation fails'
    Assert-FrpEqual 2 $script:EnrollCalls 'allocator commit then compensation enroll'
    Assert-FrpTrue ($log -match 'LOCAL_ROLLBACK=PASS') 'local rollback pass'
    Assert-FrpTrue ($log -match 'SERVER_ROLLBACK=PASS') 'server compensation pass'
    Assert-FrpTrue ($log -notmatch 'RECOVERY_REQUIRED=YES') 'no recovery required when compensation succeeds'
    Assert-FrpEqual $preToml (Get-Content -LiteralPath (Get-FrpTomlPath) -Raw) 'toml restored / port preserved'
    Assert-FrpEqual $preState (Get-Content -LiteralPath (Get-FrpStatePath) -Raw) 'state restored / port preserved'
    Assert-FrpTrue (Test-FrpDraftPending) 'draft preserved after failed apply'
    $compBody = $script:EnrollBodies[1] | ConvertFrom-Json
    $compIds = @($compBody.services | ForEach-Object { $_.id })
    Assert-FrpTrue ($compIds -contains 'rdp') 'compensation sends prior rdp'
    Assert-FrpTrue ($compIds -notcontains 'web') 'compensation does not keep uncommitted web'

    Write-FrpTestPass 'test-apply-transaction (compensation success)'

    # Compensation failure must fail loudly with RECOVERY_REQUIRED.
    $script:EnrollCalls = 0
    $script:HostLog = New-Object System.Collections.ArrayList
    $env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE = '1'
    $env:FRP_WINDOWS_FAIL_SERVER_COMPENSATE = '1'
    $rc2 = Invoke-FrpClientApplyDraft
    Remove-Item Env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_FAIL_SERVER_COMPENSATE -ErrorAction SilentlyContinue
    $log2 = ($script:HostLog -join "`n")
    Assert-FrpEqual 1 $rc2 'apply fails when compensation fails'
    Assert-FrpTrue ($log2 -match 'LOCAL_ROLLBACK=PASS') 'local rollback still pass'
    Assert-FrpTrue ($log2 -match 'SERVER_ROLLBACK=FAIL') 'server compensation fail'
    Assert-FrpTrue ($log2 -match 'RECOVERY_REQUIRED=YES') 'recovery required when server rollback fails'
    Assert-FrpEqual $preToml (Get-Content -LiteralPath (Get-FrpTomlPath) -Raw) 'toml still prior after compensation fail'
    $stateMap = ConvertTo-FrpServiceMap -Services (Read-FrpClientState).services
    Assert-FrpEqual 60030 ([int]$stateMap['rdp'].remote_port) 'prior public port preserved'

    Write-FrpTestPass 'test-apply-transaction (compensation failure)'
} finally {
    Remove-Item Env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_WINDOWS_FAIL_SERVER_COMPENSATE -ErrorAction SilentlyContinue
    Remove-Item Env:FRP_SKIP_CONNECTIVITY_CHECK -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
