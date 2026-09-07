# test-apply-identity-auth.ps1 — identity-auth apply request shape + end-to-end
# activation, with Invoke-FrpHttpsJson mocked (no real network / CA needed).
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')
try {
    # --- Enrolled client fixture -------------------------------------------------
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

    $env:FRP_SKIP_CONNECTIVITY_CHECK = '1'
    Add-FrpDraftService -Preset 'custom' -Id 'web' -Name 'Web' -TargetHost '10.0.0.5' -TargetPort 8080 | Out-Null
    Assert-FrpTrue (Test-FrpDraftPending) 'draft pending before apply'

    # --- Mock the allocator: capture the request, return a validly-signed response
    $script:CapturedBody = $null
    $script:CapturedHeaders = $null
    $script:CapturedUrl = $null

    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        $script:CapturedBody = $Body
        $script:CapturedHeaders = $Headers
        $script:CapturedUrl = $Url

        $respObj = [ordered]@{
            frp_server      = 'example.test'
            frp_server_port = 7000
            frp_transport   = 'tcp'
            services        = @(
                [ordered]@{ id = 'rdp'; remote_port = 60030 }
                [ordered]@{ id = 'web'; remote_port = 60031 }
            )
        }
        $canonicalNoHmac = Get-FrpCanonicalJson -Object $respObj
        $mac = Read-FrpIdentityMac
        $hmac = Get-FrpHmacHex -Secret $mac -Message $canonicalNoHmac
        $respObj['response_hmac'] = $hmac
        return (Get-FrpCanonicalJson -Object $respObj)
    }

    $rc = Invoke-FrpClientApplyDraft
    Assert-FrpEqual 0 $rc 'apply succeeds'

    # --- Request shape: method, url, headers, signed body ----------------------
    Assert-FrpEqual 'https://example.test/enroll' $script:CapturedUrl 'posts to allocator_url'
    Assert-FrpTrue ($null -ne $script:CapturedHeaders) 'headers captured'
    Assert-FrpEqual '1' $script:CapturedHeaders['X-Mgmt-Auth'] 'X-Mgmt-Auth header'
    Assert-FrpTrue ([string]$script:CapturedHeaders['X-Timestamp'] -match '^\d+$') 'X-Timestamp is numeric'
    Assert-FrpTrue ([string]$script:CapturedHeaders['X-Mgmt-Nonce'] -match '^[0-9a-f]{64}$') 'X-Mgmt-Nonce is 64 hex chars'
    Assert-FrpTrue ([string]$script:CapturedHeaders['X-Mgmt-Signature'].Length -gt 0) 'X-Mgmt-Signature present'
    # No X-Enrollment-ID / X-Signature (that is the enrollment-code path, not identity auth).
    Assert-FrpTrue (-not $script:CapturedHeaders.ContainsKey('X-Enrollment-ID')) 'no enrollment-code header on identity-auth apply'

    $bodyObj = $script:CapturedBody | ConvertFrom-Json
    Assert-FrpEqual $mid $bodyObj.machine_id 'body machine_id'
    Assert-FrpEqual 'win-test' $bodyObj.hostname 'body hostname'
    $bodyIds = @($bodyObj.services | ForEach-Object { $_.id })
    Assert-FrpTrue ($bodyIds -contains 'rdp') 'body includes rdp'
    Assert-FrpTrue ($bodyIds -contains 'web') 'body includes web'
    $bodyRdp = @($bodyObj.services | Where-Object { $_.id -eq 'rdp' })[0]
    Assert-FrpEqual 'custom' $bodyRdp.preset 'rdp sent as wire preset custom'

    # Signature verifies against the stored public key with the exact signed object.
    $message = Get-FrpSignedMessage -MachineId $mid -Body $script:CapturedBody `
        -Timestamp ([int64]$script:CapturedHeaders['X-Timestamp']) -Nonce $script:CapturedHeaders['X-Mgmt-Nonce'] -Op 'enroll'
    Assert-FrpTrue (Test-FrpSignature -PublicPem $id.PublicPem -Message $message -SignatureBase64 $script:CapturedHeaders['X-Mgmt-Signature']) 'request signature verifies'

    # --- End-to-end activation ---------------------------------------------------
    Assert-FrpTrue (-not (Test-FrpDraftPending)) 'draft cleared after apply'
    $state = Read-FrpClientState
    $stateMap = ConvertTo-FrpServiceMap -Services $state.services
    Assert-FrpEqual 2 $stateMap.Count 'two services committed'
    Assert-FrpEqual 60031 ([int]$stateMap['web'].remote_port) 'new service got allocated remote_port'
    Assert-FrpEqual 60030 ([int]$stateMap['rdp'].remote_port) 'existing service remote_port unchanged'
    Assert-FrpEqual 'installed' $state.install_status 'install_status installed after apply'

    $tomlText = Get-Content -LiteralPath (Get-FrpTomlPath) -Raw
    Assert-FrpTrue ($tomlText -match 'auth\.token = "tok-existing"') 'identity-auth apply reuses existing FRP token (never rotated)'
    Assert-FrpTrue ($tomlText -match 'remotePort = 60031') 'toml has new remote port'
    Assert-FrpTrue ($tomlText -match 'remotePort = 60030') 'toml keeps existing remote port'

    Write-FrpTestPass 'test-apply-identity-auth (success path)'

    # --- Failure path: bad response HMAC must not mutate local state -----------
    Add-FrpDraftService -Preset 'custom' -Id 'db' -TargetPort 5432 | Out-Null
    $preToml = (Get-Content -LiteralPath (Get-FrpTomlPath) -Raw)
    $preState = (Get-Content -LiteralPath (Get-FrpStatePath) -Raw)

    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        $respObj = [ordered]@{
            frp_server      = 'example.test'
            frp_server_port = 7000
            frp_transport   = 'tcp'
            services        = @(
                [ordered]@{ id = 'rdp'; remote_port = 60030 }
                [ordered]@{ id = 'web'; remote_port = 60031 }
                [ordered]@{ id = 'db'; remote_port = 60032 }
            )
            response_hmac   = 'deadbeef'
        }
        return (Get-FrpCanonicalJson -Object $respObj)
    }

    $rc2 = Invoke-FrpClientApplyDraft
    Assert-FrpEqual 1 $rc2 'apply fails on bad response HMAC'
    Assert-FrpTrue (Test-FrpDraftPending) 'draft preserved after failed apply'
    Assert-FrpEqual $preToml (Get-Content -LiteralPath (Get-FrpTomlPath) -Raw) 'toml unchanged after failed apply'
    Assert-FrpEqual $preState (Get-Content -LiteralPath (Get-FrpStatePath) -Raw) 'state unchanged after failed apply'

    Write-FrpTestPass 'test-apply-identity-auth (bad hmac rejected)'
} finally {
    Remove-FrpWindowsTestRoot
}
