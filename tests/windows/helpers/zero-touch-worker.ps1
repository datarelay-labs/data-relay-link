# zero-touch-worker.ps1 — one simulated Zero-Touch installer process.
# Used by test-zero-touch-lock.ps1 to run two installers against a single
# product root at the same time. The allocator is mocked in-process; the
# redeem delay widens the window so the second worker really overlaps the
# first one's mutable transaction.
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$CaSha256,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [int]$RedeemDelaySeconds = 0
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$libDir = Join-Path $repoRoot 'windows/lib'
$env:FRP_WINDOWS_ROOT = $Root

foreach ($mod in @(
        'FrpPaths.ps1', 'FrpLock.ps1', 'FrpCrypto.ps1', 'FrpTls.ps1', 'FrpState.ps1', 'FrpDraft.ps1',
        'FrpConfig.ps1', 'FrpProcess.ps1', 'FrpShim.ps1', 'FrpAutostart.ps1', 'FrpBootstrap.ps1'
    )) {
    . (Join-Path $libDir $mod)
}
Initialize-FrpCryptoTypes

$script:EnrollId = 'enroll-id-lock'
$script:EnrollSecret = 'enroll-secret-lock-do-not-use'
$script:RedeemCalls = 0
$script:EnrollCalls = 0

function Get-FrpCaCertificate {
    param([string]$AllocatorUrl, [string]$ExpectedSha256)
    $path = Get-FrpAllocatorCaPath
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    [System.IO.File]::WriteAllText($path, "-----BEGIN CERTIFICATE-----`nLOCKTEST`n-----END CERTIFICATE-----`n")
    return $path
}

function Invoke-FrpHttpsJson {
    param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
    if ($Url -like '*/bootstrap/redeem') {
        $script:RedeemCalls++
        if ($RedeemDelaySeconds -gt 0) { Start-Sleep -Seconds $RedeemDelaySeconds }
        return (Get-FrpCanonicalJson -Object ([ordered]@{
                    enrollment_code = ('{0}.{1}' -f $script:EnrollId, $script:EnrollSecret)
                    services        = @()
                }))
    }
    $script:EnrollCalls++
    $respObj = [ordered]@{
        frp_server       = 'example.test'
        frp_server_port  = 7000
        frp_transport    = 'tcp'
        token_ciphertext = (Protect-FrpTokenPbkdf2 -Token 'frp-token-lock' -Secret $script:EnrollSecret)
        services         = @()
        mgmt_status      = 'new'
    }
    $respObj['response_hmac'] = Get-FrpHmacHex -Secret $script:EnrollSecret `
        -Message (Get-FrpCanonicalJson -Object $respObj)
    return (Get-FrpCanonicalJson -Object $respObj)
}

$rc = 99
$errorText = ''
try {
    $rc = [int](Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $CaSha256 `
            -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload)
} catch {
    $rc = 98
    $errorText = [string]$_.Exception.Message
}

$result = [ordered]@{
    rc           = $rc
    pid          = $PID
    redeem_calls = $script:RedeemCalls
    enroll_calls = $script:EnrollCalls
    error        = $errorText
}
[System.IO.File]::WriteAllText($ResultPath, ($result | ConvertTo-Json -Depth 3))
exit $rc
