# test-pending-enroll-recovery.ps1 — Finding A: Zero-Touch lost-response recovery.
#
# If the HTTPS response from /bootstrap/redeem or /enroll is lost, or the
# client crashes after the allocator commits but before local state
# (client-state.json + frpc.toml + management identity) is written, the
# client must be able to resume from a local crash-safe pending-enrollment
# transaction (windows/lib/FrpState.ps1: Save-/Read-/Clear-FrpPendingEnroll)
# instead of losing the Enrollment Secret and requiring a fresh Enrollment
# Code. A used Bootstrap Ticket must never be redeemed again; resume calls
# /enroll directly with the persisted Enrollment ID/Secret (server-side
# idempotent replay is assumed, mirroring the Unix
# tests/test-pending-enroll-recovery.sh coverage against the real
# allocator), or skips the network call entirely when a cached response is
# already persisted (windows/lib/FrpBootstrap.ps1: Invoke-FrpZeroTouch).
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot '_import.ps1')

$script:AllRoots = New-Object 'System.Collections.Generic.List[string]'

function New-FrpScenarioRoot {
    <#
    .SYNOPSIS
      Fresh, isolated Windows-root test tree (own machine id / state dir),
      mirroring the separate client trees used per scenario in the Unix
      tests/test-pending-enroll-recovery.sh.
    #>
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('frp-win-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $env:FRP_WINDOWS_ROOT = $root
    $script:AllRoots.Add($root)
    Initialize-FrpDirectories
    return $root
}

function Install-FrpTestPinnedCa {
    <#
    .SYNOPSIS
      Pre-seeds a self-signed CA at the allocator-CA path so
      Get-FrpCaCertificate's "already pinned" branch short-circuits before
      any real network fetch (Invoke-FrpHttpsJson is mocked below, but
      Get-FrpCaCertificate performs its own direct HTTPS fetch and is not
      routed through that mock). Returns the DER SHA-256 hex fingerprint to
      pass as -CaSha256.
    #>
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=frp-pending-enroll-test-ca', $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(365))
    $der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $dest = Get-FrpAllocatorCaPath
    $dir = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($dest, $der)
    return (Get-FrpSha256Hex -Bytes $der)
}

try {
    $enrollId = 'enroll-id-1'
    $enrollSecret = 'enroll-secret-1-do-not-use'
    $frpToken = 'frp-plaintext-token-1'

    $script:RedeemCalls = 0
    $script:EnrollCalls = 0
    $script:EnrollShouldFail = $false

    # Mocked allocator: /bootstrap/redeem and /enroll only (no real network).
    # Overriding the module-level function by re-declaring it in this scope
    # works the same way tests/windows/test-apply-identity-auth.ps1 mocks
    # Invoke-FrpHttpsJson.
    function Invoke-FrpHttpsJson {
        param([string]$Method, [string]$Url, [string]$Body, [hashtable]$Headers, [string]$CaPath, [int]$TimeoutSec = 30)
        if ($Url -like '*/bootstrap/redeem') {
            $script:RedeemCalls++
            $resp = [ordered]@{
                enrollment_code = "$enrollId.$enrollSecret"
                services        = @(
                    [ordered]@{ id = 'rdp'; name = 'RDP'; protocol = 'tcp'; local_ip = '127.0.0.1'; local_port = 3389; preset = 'custom' }
                )
            }
            return (Get-FrpCanonicalJson -Object $resp)
        }
        if ($Url -eq 'https://example.test/enroll') {
            $script:EnrollCalls++
            if ($script:EnrollShouldFail) {
                throw 'ERROR: simulated allocator unreachable (test)'
            }
            $ciphertext = Protect-FrpTokenPbkdf2 -Token $frpToken -Secret $enrollSecret
            $respObj = [ordered]@{
                frp_server       = 'example.test'
                frp_server_port  = 7000
                frp_transport    = 'tcp'
                token_ciphertext = $ciphertext
                services         = @(
                    [ordered]@{ id = 'rdp'; remote_port = 60101 }
                )
                mgmt_status      = 'new'
            }
            $canonicalNoHmac = Get-FrpCanonicalJson -Object $respObj
            $hmac = Get-FrpHmacHex -Secret $enrollSecret -Message $canonicalNoHmac
            $respObj['response_hmac'] = $hmac
            return (Get-FrpCanonicalJson -Object $respObj)
        }
        throw "unexpected URL in test mock: $Url"
    }

    # -----------------------------------------------------------------------
    # 1. "redeemed" phase resume: /bootstrap/redeem succeeds and is
    #    persisted, but /enroll fails (lost response / allocator
    #    unreachable). Resuming with no ticket must exact-replay /enroll
    #    using the persisted secret and complete the install without ever
    #    redeeming the ticket twice.
    # -----------------------------------------------------------------------
    New-FrpScenarioRoot | Out-Null
    $caSha1 = Install-FrpTestPinnedCa
    $script:RedeemCalls = 0
    $script:EnrollCalls = 0
    $script:EnrollShouldFail = $true

    $threw = $false
    try {
        Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha1 `
            -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload | Out-Null
    } catch { $threw = $true }
    Assert-FrpTrue $threw 'attempt 1 (enroll failure) throws'
    Assert-FrpEqual 1 $script:RedeemCalls 'attempt 1 redeemed once'
    Assert-FrpEqual 1 $script:EnrollCalls 'attempt 1 attempted enroll once'
    Assert-FrpTrue (Test-FrpPendingEnrollExists) 'pending file exists after redeemed-phase crash'
    $pendingRaw1 = Get-FrpPendingEnrollRaw
    Assert-FrpEqual 'redeemed' ([string]$pendingRaw1.phase) 'pending phase=redeemed'
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Get-FrpStatePath))) 'client-state.json not yet written'

    $script:EnrollShouldFail = $false
    $rc1 = Invoke-FrpZeroTouch -AllocatorUrl '' -CaSha256 '' -BootstrapTicket '' -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc1 'resume from redeemed phase succeeds'
    Assert-FrpEqual 1 $script:RedeemCalls 'resume does not re-redeem ticket'
    Assert-FrpEqual 2 $script:EnrollCalls 'resume replays enroll exactly once more'
    Assert-FrpTrue (Test-FrpIsEnrolled) 'resume commits local state'
    Assert-FrpTrue (-not (Test-FrpPendingEnrollExists)) 'pending cleared after successful resume'
    $state1 = Read-FrpClientState
    $stateMap1 = ConvertTo-FrpServiceMap -Services $state1.services
    Assert-FrpEqual 60101 ([int]$stateMap1['rdp'].remote_port) 'resumed state has the allocated port'
    Write-FrpTestPass 'REDEEMED_PHASE_EXACT_REPLAY_RESUME'
    Write-FrpTestPass 'REDEEMED_PHASE_NO_TICKET_REUSE'
    Write-FrpTestPass 'REDEEMED_PHASE_PENDING_CLEARED_AFTER_SUCCESS'

    # A further attempt on the SAME (now fully-enrolled) host must refuse to
    # re-run zero-touch at all -- proving recovery never weakened
    # enroll-once / ticket single-use semantics.
    $rc1b = Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha1 `
        -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload
    Assert-FrpEqual 2 $rc1b 'refuse re-ticket after recovery completed'
    Assert-FrpEqual 1 $script:RedeemCalls 'refusal path never touches the allocator'
    Write-FrpTestPass 'TICKET_SINGLE_USE_PRESERVED_AFTER_RECOVERY'

    # -----------------------------------------------------------------------
    # 2. "enrolled" phase resume: /enroll succeeds and the allocator commits
    #    the reservation, but the client crashes before client-state.json is
    #    written (simulated via FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL). Resuming
    #    must reuse the cached response and finish the local commit WITHOUT
    #    another /enroll (or /bootstrap/redeem) round trip.
    # -----------------------------------------------------------------------
    New-FrpScenarioRoot | Out-Null
    $caSha2 = Install-FrpTestPinnedCa
    $script:RedeemCalls = 0
    $script:EnrollCalls = 0
    $script:EnrollShouldFail = $false
    $env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL = '1'

    $threw2 = $false
    try {
        Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha2 `
            -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload | Out-Null
    } catch { $threw2 = $true }
    Remove-Item Env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL -ErrorAction SilentlyContinue
    Assert-FrpTrue $threw2 'attempt 1 (crash-after-enroll hook) throws'
    Assert-FrpEqual 1 $script:RedeemCalls 'attempt 1 redeemed once'
    Assert-FrpEqual 1 $script:EnrollCalls 'attempt 1 enrolled once'
    Assert-FrpTrue (Test-FrpPendingEnrollExists) 'pending file exists after enrolled-phase crash'
    $pendingRaw2 = Get-FrpPendingEnrollRaw
    Assert-FrpEqual 'enrolled' ([string]$pendingRaw2.phase) 'pending phase=enrolled'
    Assert-FrpTrue ($null -ne $pendingRaw2.enroll_meta -and [string]$pendingRaw2.enroll_meta.token_ciphertext) 'cached enroll response has token_ciphertext'
    Assert-FrpTrue (@($pendingRaw2.allocated_services).Count -gt 0) 'cached allocated services present'
    Assert-FrpTrue (-not [string]::IsNullOrWhiteSpace([string]$pendingRaw2.mgmt_fingerprint)) 'mgmt fingerprint recorded'
    Assert-FrpTrue (-not (Test-Path -LiteralPath (Get-FrpStatePath))) 'client-state.json not yet written'

    $rc2 = Invoke-FrpZeroTouch -AllocatorUrl '' -CaSha256 '' -BootstrapTicket '' -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc2 'resume from enrolled phase succeeds'
    Assert-FrpEqual 1 $script:RedeemCalls 'resume does not re-redeem ticket'
    Assert-FrpEqual 1 $script:EnrollCalls 'resume makes no additional /enroll call'
    Assert-FrpTrue (Test-FrpIsEnrolled) 'resume commits local state'
    Assert-FrpTrue (-not (Test-FrpPendingEnrollExists)) 'pending cleared after successful resume'
    Write-FrpTestPass 'ENROLLED_PHASE_CACHED_RESUME_NO_NETWORK_CALL'
    Write-FrpTestPass 'ENROLLED_PHASE_PENDING_CLEARED_AFTER_SUCCESS'

    # -----------------------------------------------------------------------
    # 3. Storage properties: the enrollment secret held in the pending file
    #    must never leak into client-state.json. On a real Windows host it
    #    is DPAPI-protected; on this non-Windows test host it falls back to
    #    plain JSON, matching Save-FrpIdentityKey's existing fallback.
    # -----------------------------------------------------------------------
    New-FrpScenarioRoot | Out-Null
    $caSha3 = Install-FrpTestPinnedCa
    $script:RedeemCalls = 0
    $script:EnrollCalls = 0
    $env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL = '1'
    $threw3 = $false
    try {
        Invoke-FrpZeroTouch -AllocatorUrl 'https://example.test/enroll' -CaSha256 $caSha3 `
            -BootstrapTicket 'bt1.deadbeef.deadbeef' -SkipStart -SkipDownload | Out-Null
    } catch { $threw3 = $true }
    Remove-Item Env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL -ErrorAction SilentlyContinue
    Assert-FrpTrue $threw3 'mode-check attempt throws'
    $pendingRaw3 = Get-FrpPendingEnrollRaw
    if (Test-FrpIsWindowsHost) {
        Assert-FrpTrue ($null -ne $pendingRaw3.enroll_secret_dpapi -and [string]$pendingRaw3.enroll_secret_dpapi) 'secret DPAPI-protected on a Windows host'
        Assert-FrpTrue ([string]::IsNullOrEmpty([string]$pendingRaw3.enroll_secret)) 'no plaintext secret field on a Windows host'
    } else {
        Assert-FrpEqual $enrollSecret ([string]$pendingRaw3.enroll_secret) 'plaintext secret fallback matches on this non-Windows test host'
    }

    $rc3 = Invoke-FrpZeroTouch -AllocatorUrl '' -CaSha256 '' -BootstrapTicket '' -SkipStart -SkipDownload
    Assert-FrpEqual 0 $rc3 'mode-check resume succeeds'
    $stateText = Get-Content -LiteralPath (Get-FrpStatePath) -Raw
    Assert-FrpTrue (-not ($stateText -match '(?i)secret')) 'client-state.json never contains the word secret'
    Write-FrpTestPass 'PENDING_FILE_SECRET_NEVER_IN_CLIENT_STATE'

    # -----------------------------------------------------------------------
    # 4. Pending write/read/clear helper round-trip (unit-level, independent
    #    of the zero-touch network flow).
    # -----------------------------------------------------------------------
    New-FrpScenarioRoot | Out-Null
    Save-FrpPendingEnroll -Phase 'redeemed' -MachineId 'unit-machine-id' -Hostname 'unit-host' `
        -AllocatorUrl 'https://example.test/enroll' -EnrollmentId 'abc123' -EnrollmentSecret 's3cr3t-value' `
        -Services @([ordered]@{ id = 'web'; name = 'web'; preset = 'custom'; local_ip = '127.0.0.1'; local_port = 8080 }) | Out-Null
    Assert-FrpTrue (Test-FrpPendingEnrollExists) 'helper write creates file'
    Assert-FrpTrue (Test-FrpPendingEnrollMatches -MachineId 'unit-machine-id') 'exists_for matches'
    Assert-FrpTrue (-not (Test-FrpPendingEnrollMatches -MachineId 'other-machine-id')) 'exists_for rejects a foreign machine id'

    $loaded = Read-FrpPendingEnroll
    Assert-FrpEqual 'redeemed' $loaded.Phase 'loaded phase'
    Assert-FrpEqual 'abc123' $loaded.EnrollmentId 'loaded id'
    Assert-FrpEqual 's3cr3t-value' $loaded.EnrollmentSecret 'loaded secret round-trips'
    Assert-FrpEqual 'web' ([string]@($loaded.Services)[0].id) 'loaded services round-trip'

    Clear-FrpPendingEnroll
    Assert-FrpTrue (-not (Test-FrpPendingEnrollExists)) 'clear removes the file'
    Write-FrpTestPass 'PENDING_ENROLL_HELPERS_WRITE_LOAD_CLEAR'

    Write-FrpTestPass 'test-pending-enroll-recovery'
} finally {
    Remove-Item Env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL -ErrorAction SilentlyContinue
    foreach ($r in $script:AllRoots) {
        if (Test-Path -LiteralPath $r) { Remove-Item -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
