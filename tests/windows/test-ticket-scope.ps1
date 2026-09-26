# test-ticket-scope.ps1 — F27: the Bootstrap Ticket defines the authorized
# service scope. Local input (-ServicesJson / FRP_SERVICES_JSON) must never
# widen it, and a management-only (empty services) ticket must stay
# management-only even when the installer was given a service list. The
# allocator enforces this at /enroll; this test proves the Windows client
# never asks for more than the ticket granted.
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

function Assert-FrpEnrollServicesOmitLocalRdp {
    param($Services, [string]$Message)
    foreach ($svc in @($Services)) {
        if ($null -eq $svc) { continue }
        foreach ($field in @('id', 'name', 'preset')) {
            $value = [string]$svc.$field
            if ($value.Equals('rdp', [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "ASSERT: $Message (services.$field=$value)"
            }
        }
    }
}

function Install-FrpTestPinnedCa {
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=frp-ticket-scope-test-ca', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(365))
    $der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $dest = Get-FrpAllocatorCaPath
    $dir = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($dest, $der)
    return (Get-FrpSha256Hex -Bytes $der)
}

try {
    $enrollId = 'enroll-id-scope'
    $enrollSecret = 'enroll-secret-scope-do-not-use'
    $frpToken = 'frp-plaintext-token-scope'

    # Ticket grants nothing: management-only enrollment.
    $script:TicketServices = @()
    $script:EnrollBody = $null

    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        if ($Url -like '*/bootstrap/redeem') {
            return (Get-FrpCanonicalJson -Object ([ordered]@{
                        enrollment_code = "$enrollId.$enrollSecret"
                        services        = @($script:TicketServices)
                    }))
        }
        if ($Url -eq 'https://example.test/enroll') {
            $script:EnrollBody = $Body
            # Mirror the allocator: it only ever allocates ports for services
            # inside the ticket scope.
            $port = 60100
            $allocated = @(@($script:TicketServices) | ForEach-Object {
                    $port++
                    [ordered]@{ id = [string]$_.id; remote_port = $port }
                })
            $respObj = [ordered]@{
                frp_server       = 'example.test'
                frp_server_port  = 7000
                frp_transport    = 'tcp'
                token_ciphertext = (Protect-FrpTokenPbkdf2 -Token $frpToken -Secret $enrollSecret)
                services         = @($allocated)
                mgmt_status      = 'new'
            }
            $respObj['response_hmac'] = Get-FrpHmacHex -Secret $enrollSecret `
                -Message (Get-FrpCanonicalJson -Object $respObj)
            return (Get-FrpCanonicalJson -Object $respObj)
        }
        throw "unexpected URL in test mock: $Url"
    }

    $caSha = Install-FrpTestPinnedCa
    $servicesJson = '[{"id":"rdp","name":"RDP","preset":"rdp","protocol":"tcp","local_ip":"127.0.0.1","local_port":3389}]'
    $env:FRP_SERVICES_JSON = $servicesJson

    $rc = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha `
        -BootstrapTicket 'bt1.deadbeef.deadbeef' -ServicesJson $servicesJson -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc 'management-only zero-touch succeeds'

    Assert-FrpTrue ($null -ne $script:EnrollBody) '/enroll was called'
    $sent = $script:EnrollBody | ConvertFrom-Json
    Assert-FrpEqual 0 @($sent.services).Count 'empty ticket does not expand services at /enroll'
    # Parsed services only. The enroll body also carries a fresh mgmt_pubkey,
    # whose Base64 can contain the letters "rdp" without any RDP service.
    Assert-FrpEnrollServicesOmitLocalRdp $sent.services 'local service input never reaches the enroll request'

    $state = Read-FrpClientState
    Assert-FrpTrue ($state.management_only -eq $true) 'client stays management-only'
    Assert-FrpEqual 0 @($state.services.PSObject.Properties).Count 'no services persisted locally'
    Assert-FrpEqual 'management_only' (Get-FrpInstallStatus) 'status management_only'

    $toml = Get-Content -LiteralPath (Get-FrpTomlPath) -Raw
    Assert-FrpTrue (-not ($toml -match '\[\[proxies\]\]')) 'no proxies in frpc.toml'

    # A ticket that does grant a service is still honoured exactly.
    Remove-FrpWindowsTestRoot
    $env:FRP_WINDOWS_ROOT = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $env:FRP_WINDOWS_ROOT -Force | Out-Null
    Initialize-FrpDirectories
    $caSha2 = Install-FrpTestPinnedCa
    $script:TicketServices = @(
        [ordered]@{ id = 'ssh'; name = 'SSH'; protocol = 'tcp'; local_ip = '127.0.0.1'; local_port = 22; preset = 'ssh'; ssh_user = 'aella' }
    )
    $script:EnrollBody = $null

    $rc2 = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha2 `
        -BootstrapTicket 'bt1.deadbeef.deadbeef' -ServicesJson $servicesJson -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc2 'ssh ticket zero-touch completes'
    $sent2 = $script:EnrollBody | ConvertFrom-Json
    Assert-FrpEqual 1 @($sent2.services).Count 'ticket service count preserved'
    Assert-FrpEqual 'ssh' ([string]@($sent2.services)[0].id) 'ticket service id preserved'
    Assert-FrpEnrollServicesOmitLocalRdp $sent2.services 'local service input never appended to ticket scope'

    # F12: an absent services field is a malformed redeem response; an empty
    # list is a valid management-only ticket.
    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        return (Get-FrpCanonicalJson -Object ([ordered]@{ enrollment_code = "$enrollId.$enrollSecret" }))
    }
    $threwMissing = $false
    try {
        Invoke-FrpBootstrapRedeem -AllocatorUrl 'https://example.test/enroll' `
            -Ticket 'bt1.deadbeef.deadbeef' -MachineId 'm' -Hostname 'h' | Out-Null
    } catch { $threwMissing = $true }
    Assert-FrpTrue $threwMissing 'missing services field in redeem response is rejected'

    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        return (Get-FrpCanonicalJson -Object ([ordered]@{ enrollment_code = "$enrollId.$enrollSecret"; services = @() }))
    }
    $redeemed = Invoke-FrpBootstrapRedeem -AllocatorUrl 'https://example.test/enroll' `
        -Ticket 'bt1.deadbeef.deadbeef' -MachineId 'm' -Hostname 'h'
    Assert-FrpEqual 0 @($redeemed.Services).Count 'empty services list is a valid management-only ticket'

    Write-FrpTestPass 'test-ticket-scope'
} finally {
    Remove-Item Env:FRP_SERVICES_JSON -ErrorAction SilentlyContinue
    Remove-FrpWindowsTestRoot
}
